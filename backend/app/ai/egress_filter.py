import re
import json
import logging
from typing import Any, Optional, Dict
from sqlalchemy.orm import Session
from app.audit.service import log_audit_event
from app.models.security_alert import SecurityAlert

logger = logging.getLogger(__name__)

class AIEgressLeakDetectedException(Exception):
    """Raised when the AI egress filter detects an attempt to leak DEKs or ciphertext."""
    pass

class AIEgressFilter:
    """
    Phase 6 / Invariant I6 Egress Filter:
    Inspects all outbound network payloads to external AI endpoints (e.g., Google Gemini).
    Asserts zero Data Encryption Keys (DEKs), ciphertext chunks, or raw binary content bytes.
    On detection: drops the request, logs a CRITICAL audit event, and creates a threat alert.
    """

    # 64-char hex strings representing 256-bit raw cryptographic keys
    HEX_KEY_REGEX = re.compile(r"\b[0-9a-fA-F]{64}\b")

    # Base64 encoded 32-byte (256-bit) keys (43 chars + '=')
    BASE64_KEY_REGEX = re.compile(r"\b[A-Za-z0-9+/]{43}=\b")

    # Chunk / ciphertext artifact signatures
    CIPHERTEXT_SIGNATURES = [
        "aes-256-gcm-chunk",
        "wrapped_dek",
        "encrypted_chunk_",
        "TrustVault-Chunk-Tag"
    ]

    @classmethod
    def scan_text(cls, text_content: str) -> Optional[str]:
        """
        Inspects text for leak signatures.
        Returns the violation reason if detected, or None if safe.
        """
        if not text_content:
            return None

        # Check for raw 256-bit hex keys
        hex_matches = cls.HEX_KEY_REGEX.findall(text_content)
        # Avoid false positives for standard UUIDs (which contain hyphens)
        if hex_matches:
            # Check if any match is pure hex without hyphens
            for m in hex_matches:
                return f"Raw 256-bit cryptographic hex key detected: {m[:8]}...{m[-8:]}"

        # Check for base64-encoded 256-bit keys
        b64_matches = cls.BASE64_KEY_REGEX.findall(text_content)
        if b64_matches:
            return f"Base64-encoded 256-bit key detected: {b64_matches[0][:8]}..."

        # Check for ciphertext / envelope chunk signatures
        lower_text = text_content.lower()
        for sig in cls.CIPHERTEXT_SIGNATURES:
            if sig.lower() in lower_text:
                return f"Ciphertext chunk / envelope artifact detected: '{sig}'"

        return None

    @classmethod
    def inspect_payload(cls, data: Any) -> Optional[str]:
        """
        Recursively scans payloads (dict, list, string, bytes) for leak signatures.
        """
        if isinstance(data, (bytes, bytearray)):
            return f"Raw binary bytes payload ({len(data)} bytes) forbidden in AI egress"

        if isinstance(data, str):
            reason = cls.scan_text(data)
            if reason:
                return reason

        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str):
                    r_k = cls.scan_text(k)
                    if r_k:
                        return r_k
                r_v = cls.inspect_payload(v)
                if r_v:
                    return r_v

        elif isinstance(data, (list, tuple, set)):
            for item in data:
                r_item = cls.inspect_payload(item)
                if r_item:
                    return r_item

        return None

    @classmethod
    def assert_safe_and_alert_on_leak(
        cls,
        payload: Any,
        db: Optional[Session] = None,
        actor_id: Optional[str] = None,
        request_id: Optional[str] = None,
        document_id: Optional[str] = None
    ) -> None:
        """
        Validates the outbound payload.
        If a leak is detected:
        1. Immediately aborts and drops the request
        2. Emits a CRITICAL audit event
        3. Creates a critical SecurityAlert
        4. Raises AIEgressLeakDetectedException
        """
        violation = cls.inspect_payload(payload)
        if not violation:
            return

        # Egress violation detected!
        logger.critical(f"AI EGRESS LEAK BLOCKED: {violation} (Actor: {actor_id}, Doc: {document_id})")

        # 1. Log CRITICAL audit event
        if db:
            try:
                log_audit_event(
                    db=db,
                    action="threat.ai_egress_leak_blocked",
                    resource_type="ai_egress_filter",
                    resource_id=document_id or "global",
                    outcome="critical",
                    actor_id=actor_id,
                    request_id=request_id,
                    metadata={
                        "violation_reason": violation,
                        "document_id": document_id
                    }
                )
            except Exception as e:
                logger.error(f"Failed to log audit event for AI egress leak: {e}")

            # 2. Create SecurityAlert
            try:
                alert = SecurityAlert(
                    event_type="AI_EGRESS_LEAK_BLOCKED",
                    severity="critical",
                    status="open",
                    actor_id=actor_id,
                    target_document_id=document_id,
                    request_id=request_id,
                    summary=f"AI Egress Filter blocked unauthorized outbound data/key leak: {violation}",
                    investigation_metadata={
                        "violation": violation,
                        "document_id": document_id
                    }
                )
                db.add(alert)
                db.commit()
            except Exception as e:
                logger.error(f"Failed to create security alert for AI egress leak: {e}")

        raise AIEgressLeakDetectedException(
            f"Security Violation: AI egress filter blocked unauthorized outbound transmission ({violation})"
        )
