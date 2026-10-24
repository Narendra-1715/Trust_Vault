"""ContentService: Confidential Document Envelope Encryption & Decryption Engine
Sole entry point for decrypting content, enforcing Admin Blindness (Invariant I1).
- Generates random 256-bit DEK per document version.
- Encrypts in 64 KiB chunks with AES-256-GCM and unique 96-bit nonces.
- Cryptographically binds chunk AAD: (document_id, version_id, chunk_index, is_final).
- Streaming integrity verification on read (GCM tag per chunk + end-of-stream SHA-256).
- Hard purge = crypto-shredding: deleting the DEK destroys content across all disks and backups.
"""

import os
import io
import time
import struct
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Generator, BinaryIO, Optional, Tuple, Dict, Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.models.user import User
from app.models.document import Document
from app.models.document_version import DocumentVersion
from app.models.document_key import DocumentKey
from app.services.authorization import AuthorizationService, Action, raise_not_found
from app.services.key_provider import get_key_provider, KeyProvider
from app.storage.local import storage_service
from app.audit.service import log_audit_event
from app.notifications.service import create_security_notification

MAGIC_HEADER = b"TV01\x00\x00\x00\x01"  # TrustVault Envelope Format v1
CHUNK_SIZE = 64 * 1024  # 64 KiB

class ContentService:
    """
    Confidential Document Content Service.
    Guarantees private opaque storage (Invariant I4) and Admin Blindness (Invariant I1).
    """

    @classmethod
    def encrypt_and_store(
        cls,
        db: Session,
        principal: User,
        document_id: str,
        version_id: Optional[str],
        file_obj: BinaryIO,
        key_provider: Optional[KeyProvider] = None
    ) -> Tuple[str, int, str]:
        """
        Envelope-encrypts plaintext file in 64 KiB chunks with AES-256-GCM.
        Generates random 256-bit DEK, wraps it with KEK, and writes framed ciphertext to private storage.
        Returns: (storage_key, plaintext_total_size, plaintext_sha256).
        """
        kp = key_provider or get_key_provider()

        # 1. Generate random 256-bit Data Encryption Key (DEK)
        dek = secrets.token_bytes(32)

        # 2. Wrap DEK with Key-Encryption-Key (KEK)
        wrapped_dek, kek_id = kp.wrap_key(dek)

        # 3. Store wrapped DEK in document_keys table
        doc_key = DocumentKey(
            document_id=document_id,
            version_id=version_id,
            wrapped_dek=wrapped_dek,
            kek_id=kek_id,
            algorithm="AES-256-GCM",
            chunk_size=CHUNK_SIZE,
            created_at=datetime.now(timezone.utc)
        )
        db.add(doc_key)

        # 4. Stream and encrypt in 64 KiB chunks with AAD binding
        aesgcm = AESGCM(dek)
        hasher = hashlib.sha256()
        plaintext_total_bytes = 0
        storage_key = f"{secrets.token_hex(16)}.bin"

        # Buffer incoming file chunks to determine is_final for AAD binding
        chunks = []
        while chunk := file_obj.read(CHUNK_SIZE):
            plaintext_total_bytes += len(chunk)
            hasher.update(chunk)
            chunks.append(chunk)

        # Handle empty file case
        if not chunks:
            chunks = [b""]

        encrypted_payload = bytearray(MAGIC_HEADER)
        total_chunks = len(chunks)

        for index, chunk in enumerate(chunks):
            is_final = 1 if (index == total_chunks - 1) else 0
            # Unique 96-bit (12 bytes) nonce per chunk
            nonce = secrets.token_bytes(12)
            # AAD binding: (document_id, version_id, chunk_index, is_final)
            # Prevents chunk reordering, truncation, or cross-document swapping
            aad = f"{document_id}:{version_id or ''}:{index}:{is_final}".encode("utf-8")
            ciphertext = aesgcm.encrypt(nonce, chunk, associated_data=aad)

            # Frame format:
            # [4B total chunk payload length][4B chunk_index][1B is_final][12B nonce][ciphertext + 16B GCM tag]
            payload_len = len(nonce) + len(ciphertext)
            encrypted_payload.extend(struct.pack(">IIB", payload_len, index, is_final))
            encrypted_payload.extend(nonce)
            encrypted_payload.extend(ciphertext)

        # 5. Persist framed ciphertext to private opaque volume
        class EncryptedBufferStream:
            def __init__(self, data: bytes):
                self.stream = io.BytesIO(data)
            def read(self, size=-1):
                return self.stream.read(size)

        storage_service.save_file(EncryptedBufferStream(bytes(encrypted_payload)), storage_key)

        plaintext_checksum = hasher.hexdigest()
        return storage_key, plaintext_total_bytes, plaintext_checksum

    @classmethod
    def stream(
        cls,
        db: Session,
        principal: Optional[User],
        document_id: str,
        version_id: Optional[str] = None,
        request_id: Optional[str] = None,
        revalidate_chunks: int = 10,
        revalidate_seconds: float = 2.0
    ) -> Generator[bytes, None, None]:
        """
        Authenticated decryption streaming:
        THE DECRYPT PATH IS REACHABLE ONLY VIA THIS METHOD.
        1. Calls AuthorizationService.decide to verify authorization against live DB state.
        2. Retrieves wrapped DEK and unwraps with KMS/KeyProvider.
        3. Decrypts chunk by chunk, verifying AES-256-GCM authentication tags and AAD bindings.
        4. Verifies end-to-end plaintext SHA-256 checksum at the end of stream.
        5. Aborts immediately and raises threat alerts if any chunk is tampered or swapped.
        """
        # 1. Authorize principal via central Policy Decision Point (PDP)
        version = None
        if version_id:
            version = db.query(DocumentVersion).filter(
                DocumentVersion.id == version_id,
                DocumentVersion.document_id == document_id
            ).first()
            if not version:
                raise_not_found()
        else:
            version = db.query(DocumentVersion).filter(
                DocumentVersion.document_id == document_id,
                DocumentVersion.is_current == True
            ).first()
            if version:
                version_id = version.id

        context = {"version_number": version.version_number} if version else None
        decision = AuthorizationService.decide(db, principal, Action.DOWNLOAD, document_id, context)
        if not decision.allowed:
            actor_id = principal.id if principal else None
            try:
                log_audit_event(
                    db=db,
                    action="document.download.denied",
                    resource_type="document",
                    resource_id=document_id,
                    outcome="denied",
                    actor_id=actor_id,
                    request_id=request_id or "stream",
                    metadata={"reason": decision.reason}
                )
            except Exception:
                pass
            raise_not_found()

        doc = decision.document

        # 2. Determine target storage key and expected checksum
        storage_key = version.storage_key if version else doc.internal_storage_key
        expected_checksum = version.checksum if version else doc.checksum

        # 3. Locate wrapped DEK in document_keys
        key_query = db.query(DocumentKey).filter(DocumentKey.document_id == document_id)
        if version_id:
            key_query = key_query.filter(DocumentKey.version_id == version_id)
        doc_key = key_query.first()

        # If no key found for specific version, check document-level key
        if not doc_key and version_id:
            doc_key = db.query(DocumentKey).filter(
                DocumentKey.document_id == document_id,
                DocumentKey.version_id.is_(None)
            ).first()

        # 4. Check for legacy unencrypted file support (backwards compatibility)
        if not storage_service.exists(storage_key):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Storage object missing from private volume."
            )

        # Read first 8 bytes to verify envelope header
        raw_stream = storage_service.read_file_stream(storage_key, chunk_size=8)
        header_bytes = b""
        try:
            header_bytes = next(raw_stream)
        except StopIteration:
            pass

        # If document key exists, the file was envelope-encrypted and MUST start with MAGIC_HEADER
        if doc_key and header_bytes != MAGIC_HEADER:
            _trigger_tamper_alert(db, document_id, principal, "File header corrupted or tampered on disk.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File integrity check failed: Corrupted envelope header."
            )

        # If file is legacy unencrypted format without TV01 header:
        if header_bytes != MAGIC_HEADER:
            # Yield raw stream directly for backwards-compatibility
            def legacy_stream():
                last_reval_time = time.time()
                chunks_since_last_reval = 0
                yield header_bytes
                for c in storage_service.read_file_stream(storage_key, chunk_size=CHUNK_SIZE):
                    chunks_since_last_reval += 1
                    now_time = time.time()
                    if chunks_since_last_reval >= revalidate_chunks or (now_time - last_reval_time) >= revalidate_seconds:
                        chunks_since_last_reval = 0
                        last_reval_time = now_time
                        db.expire_all()
                        midstream_decision = AuthorizationService.decide(
                            db=db,
                            principal=principal,
                            action=Action.DOWNLOAD,
                            resource_id=document_id,
                            context=context
                        )
                        if not midstream_decision.allowed:
                            log_audit_event(
                                db=db,
                                action="document.download.revoked_mid_stream",
                                resource_type="document",
                                resource_id=document_id,
                                outcome="denied",
                                actor_id=principal.id if principal else None,
                                request_id=request_id or "midstream",
                                metadata={"reason": "Permission revoked or expired mid-stream"}
                            )
                            raise HTTPException(
                                status_code=status.HTTP_403_FORBIDDEN,
                                detail="Access grant has been revoked or expired mid-stream."
                            )
                    yield c
            return legacy_stream()

        if not doc_key:
            # Crypto-shredded! The DEK has been destroyed, rendering the ciphertext unrecoverable
            log_audit_event(
                db=db,
                action="document.content.crypto_shredded_access_attempt",
                resource_type="document",
                resource_id=document_id,
                outcome="denied",
                actor_id=principal.id if principal else None,
                request_id=request_id or "stream",
                metadata={"reason": "Wrapped DEK destroyed; content is permanently unrecoverable"}
            )
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Document content has been permanently crypto-shredded."
            )

        # 5. Unwrap DEK with KEK
        kp = get_key_provider()
        try:
            dek = kp.unwrap_key(doc_key.wrapped_dek, doc_key.kek_id)
        except Exception as e:
            log_audit_event(
                db=db,
                action="document.content.dek_unwrap_failed",
                resource_type="document",
                resource_id=document_id,
                outcome="failure",
                actor_id=principal.id if principal else None,
                request_id=request_id or "stream",
                metadata={"error": str(e)}
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to unwrap document encryption key."
            )

        aesgcm = AESGCM(dek)

        # 6. Generator for streaming decryption and integrity verification
        def decrypt_generator():
            last_reval_time = time.time()
            chunks_since_last_reval = 0
            full_raw_stream = storage_service.read_file_stream(storage_key, chunk_size=1024 * 1024)
            buffer = bytearray()
            # Consume magic header
            header_consumed = False
            expected_chunk_index = 0
            stream_hasher = hashlib.sha256()

            for chunk_data in full_raw_stream:
                buffer.extend(chunk_data)
                if not header_consumed:
                    if len(buffer) < len(MAGIC_HEADER):
                        continue
                    if bytes(buffer[:len(MAGIC_HEADER)]) != MAGIC_HEADER:
                        raise HTTPException(status_code=500, detail="Corrupted envelope header.")
                    buffer = buffer[len(MAGIC_HEADER):]
                    header_consumed = True

                # Process all complete framed chunks in buffer
                while len(buffer) >= 9:  # 4B length + 4B index + 1B is_final
                    payload_len, chunk_index, is_final = struct.unpack(">IIB", buffer[:9])
                    frame_total = 9 + payload_len

                    if len(buffer) < frame_total:
                        break  # Wait for more bytes

                    if chunk_index != expected_chunk_index:
                        # Chunk reordering / truncation attack detected!
                        _trigger_tamper_alert(db, document_id, principal, f"Chunk reordering attack: expected {expected_chunk_index}, got {chunk_index}")
                        raise HTTPException(status_code=500, detail="Data integrity check failed: Chunk sequence anomaly.")

                    frame_payload = buffer[9:frame_total]
                    buffer = buffer[frame_total:]

                    if len(frame_payload) < 28:  # 12B nonce + 16B tag
                        _trigger_tamper_alert(db, document_id, principal, "Truncated chunk payload")
                        raise HTTPException(status_code=500, detail="Data integrity check failed: Truncated chunk.")

                    nonce = bytes(frame_payload[:12])
                    ciphertext_and_tag = bytes(frame_payload[12:])

                    # AAD binding verification
                    aad = f"{document_id}:{version_id or ''}:{chunk_index}:{is_final}".encode("utf-8")
                    try:
                        plaintext_chunk = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=aad)
                    except InvalidTag:
                        # Ciphertext tampered or swapped across documents!
                        _trigger_tamper_alert(db, document_id, principal, f"AES-GCM tag mismatch on chunk {chunk_index}. Tampering or swapped chunk detected.")
                        raise HTTPException(status_code=500, detail="Data integrity check failed: Tampered or swapped ciphertext chunk.")

                    # Invariant I2 (Instant Revocation): Re-validate authorization synchronously against live DB
                    # every N chunks or every 2 seconds, whichever comes first
                    chunks_since_last_reval += 1
                    now_time = time.time()
                    if chunks_since_last_reval >= revalidate_chunks or (now_time - last_reval_time) >= revalidate_seconds:
                        chunks_since_last_reval = 0
                        last_reval_time = now_time
                        db.expire_all()
                        midstream_decision = AuthorizationService.decide(
                            db=db,
                            principal=principal,
                            action=Action.DOWNLOAD,
                            resource_id=document_id,
                            context=context
                        )
                        if not midstream_decision.allowed:
                            log_audit_event(
                                db=db,
                                action="document.download.revoked_mid_stream",
                                resource_type="document",
                                resource_id=document_id,
                                outcome="denied",
                                actor_id=principal.id if principal else None,
                                request_id=request_id or "midstream",
                                metadata={
                                    "reason": "Permission revoked or expired mid-stream",
                                    "chunk_index": chunk_index,
                                    "recheck_reason": midstream_decision.reason
                                }
                            )
                            raise HTTPException(
                                status_code=status.HTTP_403_FORBIDDEN,
                                detail="Access grant has been revoked or expired mid-stream."
                            )

                    stream_hasher.update(plaintext_chunk)
                    expected_chunk_index += 1
                    yield plaintext_chunk

            # Verify end-of-stream plaintext SHA-256 against recorded checksum
            if expected_checksum:
                computed_hash = stream_hasher.hexdigest()
                if computed_hash != expected_checksum:
                    _trigger_tamper_alert(db, document_id, principal, f"End-of-stream checksum mismatch: expected {expected_checksum}, computed {computed_hash}")
                    raise HTTPException(status_code=500, detail="Data integrity check failed: Checksum mismatch.")

        return decrypt_generator()

    @classmethod
    def crypto_shred(cls, db: Session, document_id: str, version_id: Optional[str] = None, actor_id: Optional[str] = None) -> int:
        """
        Hard purge via crypto-shredding (Invariant I1 & Phase 2 guarantee):
        Permanently destroys the wrapped DEK in document_keys table.
        Renders all encrypted disk files and historical backups mathematically unrecoverable.
        """
        query = db.query(DocumentKey).filter(DocumentKey.document_id == document_id)
        if version_id:
            query = query.filter(DocumentKey.version_id == version_id)

        count = query.delete(synchronize_session=False)
        db.commit()

        log_audit_event(
            db=db,
            action="document.content.crypto_shredded",
            resource_type="document",
            resource_id=document_id,
            outcome="success",
            actor_id=actor_id,
            request_id="crypto-shred",
            metadata={"shredded_keys_count": count, "version_id": version_id, "actor": "SYSTEM" if not actor_id else None}
        )
        return count

    @classmethod
    def rotate_kek(cls, db: Session, new_kek_id: str, new_kek_bytes: Optional[bytes] = None, actor_id: Optional[str] = None) -> int:
        """
        KEK Rotation:
        Rewraps all DEKs under new KEK without re-encrypting underlying content on disk.
        """
        kp = get_key_provider()
        if hasattr(kp, "add_kek_version") and new_kek_bytes:
            kp.add_kek_version(new_kek_id, new_kek_bytes)

        keys = db.query(DocumentKey).all()
        rotated_count = 0
        now = datetime.now(timezone.utc)

        for dk in keys:
            if dk.kek_id != new_kek_id:
                new_wrapped, updated_kek_id = kp.rotate_key(dk.wrapped_dek, dk.kek_id)
                dk.wrapped_dek = new_wrapped
                dk.kek_id = updated_kek_id
                dk.rotated_at = now
                rotated_count += 1

        db.commit()

        log_audit_event(
            db=db,
            action="kms.kek_rotated",
            resource_type="kms_key",
            resource_id=new_kek_id,
            outcome="success",
            actor_id=actor_id,
            request_id="kek-rotation",
            metadata={"rotated_keys_count": rotated_count, "new_kek_id": new_kek_id, "actor": "SYSTEM" if not actor_id else None}
        )
        return rotated_count

def _trigger_tamper_alert(db: Session, document_id: str, principal: Optional[User], reason: str):
    """Logs critical security event and dispatches urgent threat alert."""
    actor_id = principal.id if principal else None
    try:
        log_audit_event(
            db=db,
            action="document.content.integrity_compromised",
            resource_type="document",
            resource_id=document_id,
            outcome="failure",
            actor_id=actor_id,
            request_id="integrity-monitor",
            metadata={"alert": "CRITICAL", "reason": reason}
        )
        target_user_id = actor_id
        doc = db.query(Document).filter(Document.id == document_id).first()
        if doc and doc.owner_id:
            target_user_id = doc.owner_id

        if target_user_id:
            create_security_notification(
                db=db,
                user_id=target_user_id,
                title="CRITICAL: Document Ciphertext Tampering Detected",
                message=f"Cryptographic integrity verification failed for document {document_id}: {reason}",
                severity="critical",
                event_type="document.integrity.tampered",
                resource_id=document_id
            )
    except Exception:
        pass
