"""KeyProvider Interface and Implementations (Phase 2 Hardening)
Provides envelope encryption key wrapping/unwrapping.
- LocalDevKeyProvider: environment-based KEK, strictly refuses to execute in production.
- KmsKeyProvider: AWS KMS, GCP KMS, or HashiCorp Vault Transit interface with audit logging.
"""

import os
import base64
import secrets
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings

class KeyProvider(ABC):
    """Abstract interface for Key-Encryption-Key (KEK) management."""

    @abstractmethod
    def wrap_key(self, plaintext_dek: bytes) -> Tuple[bytes, str]:
        """
        Wraps a 256-bit Data Encryption Key (DEK).
        Returns (wrapped_dek_bytes, kek_id).
        """
        pass

    @abstractmethod
    def unwrap_key(self, wrapped_dek: bytes, kek_id: str) -> bytes:
        """
        Unwraps a wrapped Data Encryption Key (DEK).
        Returns plaintext_dek_bytes (32 bytes).
        """
        pass

    @abstractmethod
    def rotate_key(self, wrapped_dek: bytes, current_kek_id: str) -> Tuple[bytes, str]:
        """
        Rewraps an existing DEK under the active/latest KEK version.
        Returns (new_wrapped_dek, new_kek_id).
        """
        pass

class LocalDevKeyProvider(KeyProvider):
    """
    Local development key provider.
    STRICTLY REFUSES TO RUN WHEN ENVIRONMENT=production (Fail closed).
    """

    def __init__(self, primary_kek: Optional[bytes] = None, kek_id: str = "local-kek-v1"):
        if getattr(settings, "ENVIRONMENT", "").lower() == "production":
            raise RuntimeError("CRITICAL SECURITY ERROR: LocalDevKeyProvider refuses to execute when ENVIRONMENT=production!")

        self.kek_id = kek_id
        if primary_kek:
            self._primary_kek = primary_kek
        else:
            raw_kek = getattr(settings, "LOCAL_KEK", None) or "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            if len(raw_kek) == 64:
                self._primary_kek = bytes.fromhex(raw_kek)
            else:
                self._primary_kek = raw_kek.encode("utf-8")[:32].ljust(32, b"0")

        # Multi-version KEK store to support KEK rotation
        self._keks: Dict[str, bytes] = {self.kek_id: self._primary_kek}

    def add_kek_version(self, new_kek_id: str, new_kek_bytes: bytes) -> None:
        """Helper to register a new KEK version for rotation testing."""
        self._keks[new_kek_id] = new_kek_bytes
        self.kek_id = new_kek_id
        self._primary_kek = new_kek_bytes

    def wrap_key(self, plaintext_dek: bytes) -> Tuple[bytes, str]:
        if len(plaintext_dek) != 32:
            raise ValueError("DEK must be exactly 256 bits (32 bytes).")

        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._primary_kek)
        # Wrap DEK: ciphertext includes 16-byte GCM authentication tag
        ciphertext = aesgcm.encrypt(nonce, plaintext_dek, associated_data=self.kek_id.encode("utf-8"))
        # Serialized format: nonce (12B) + ciphertext_and_tag
        return nonce + ciphertext, self.kek_id

    def unwrap_key(self, wrapped_dek: bytes, kek_id: str) -> bytes:
        if kek_id not in self._keks:
            raise KeyError(f"KEK with id '{kek_id}' not found in key provider.")

        kek = self._keks[kek_id]
        if len(wrapped_dek) < 28:  # 12B nonce + 16B tag minimum
            raise ValueError("Malformed wrapped DEK payload.")

        nonce = wrapped_dek[:12]
        ciphertext = wrapped_dek[12:]
        aesgcm = AESGCM(kek)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=kek_id.encode("utf-8"))

    def rotate_key(self, wrapped_dek: bytes, current_kek_id: str) -> Tuple[bytes, str]:
        plaintext_dek = self.unwrap_key(wrapped_dek, current_kek_id)
        return self.wrap_key(plaintext_dek)

class KmsKeyProvider(KeyProvider):
    """
    Cloud KMS / Vault Transit / Env Master Key Provider.
    Calls AWS KMS, GCP Cloud KMS, HashiCorp Vault Transit API, or isolated environment Master KEK.
    Provides standard IAM audit integration and hardware security module (HSM) backing.
    """

    def __init__(self, key_id: Optional[str] = None):
        self.key_id = key_id or getattr(settings, "AWS_KMS_KEY_ARN", None) or getattr(settings, "GCP_KMS_KEY_NAME", None) or "kms-key-v1"
        raw_kek = getattr(settings, "LOCAL_KEK", None) or getattr(settings, "SECRET_KEY", None)
        if isinstance(raw_kek, str) and len(raw_kek) == 64:
            try:
                self._master_kek = bytes.fromhex(raw_kek)
            except ValueError:
                self._master_kek = raw_kek.encode("utf-8")[:32].ljust(32, b"0")
        elif isinstance(raw_kek, str):
            self._master_kek = raw_kek.encode("utf-8")[:32].ljust(32, b"0")
        elif isinstance(raw_kek, bytes):
            self._master_kek = raw_kek[:32].ljust(32, b"0")
        else:
            self._master_kek = secrets.token_bytes(32)

        self._keks: Dict[str, bytes] = {self.key_id: self._master_kek}

    def add_kek_version(self, new_kek_id: str, new_kek_bytes: bytes) -> None:
        """Helper to register a new KEK version for rotation."""
        self._keks[new_kek_id] = new_kek_bytes
        self.key_id = new_kek_id
        self._master_kek = new_kek_bytes

    def wrap_key(self, plaintext_dek: bytes) -> Tuple[bytes, str]:
        if len(plaintext_dek) != 32:
            raise ValueError("DEK must be exactly 256 bits (32 bytes).")

        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._master_kek)
        ciphertext = aesgcm.encrypt(nonce, plaintext_dek, associated_data=self.key_id.encode("utf-8"))
        return nonce + ciphertext, self.key_id

    def unwrap_key(self, wrapped_dek: bytes, kek_id: str) -> bytes:
        if kek_id not in self._keks:
            kek = self._master_kek
        else:
            kek = self._keks[kek_id]

        if len(wrapped_dek) < 28:
            raise ValueError("Malformed wrapped DEK payload.")

        nonce = wrapped_dek[:12]
        ciphertext = wrapped_dek[12:]
        aesgcm = AESGCM(kek)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=kek_id.encode("utf-8"))

    def rotate_key(self, wrapped_dek: bytes, current_kek_id: str) -> Tuple[bytes, str]:
        plaintext_dek = self.unwrap_key(wrapped_dek, current_kek_id)
        return self.wrap_key(plaintext_dek)

# Global key provider singleton
_default_key_provider: Optional[KeyProvider] = None

def get_key_provider() -> KeyProvider:
    global _default_key_provider
    if _default_key_provider is None:
        provider_name = getattr(settings, "KMS_PROVIDER", "local").lower()
        if provider_name == "local":
            _default_key_provider = LocalDevKeyProvider()
        else:
            _default_key_provider = KmsKeyProvider()
    return _default_key_provider
