import os
import re
from typing import BinaryIO, Generator, Tuple
from fastapi import HTTPException, status
from app.core.config import settings
from app.storage.base import BaseStorageAdapter

# Known magic bytes / file signatures
FILE_SIGNATURES = {
    "pdf": [b"%PDF"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
}

class LocalPrivateStorage(BaseStorageAdapter):
    """
    Private local filesystem storage adapter.
    Enforces strict path-traversal prevention and private directory containment.
    """

    def __init__(self, base_dir: str = settings.STORAGE_DIR):
        self.base_dir = os.path.realpath(os.path.abspath(base_dir))
        os.makedirs(self.base_dir, exist_ok=True)

    def _resolve_safe_path(self, storage_key: str) -> str:
        """
        Validates that the storage key is safe and stays strictly within base_dir.
        Defends against directory traversal (e.g. '../', null bytes).
        """
        if not storage_key or ".." in storage_key or "/" in storage_key or "\\" in storage_key or "\0" in storage_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid storage key detected."
            )
        target_path = os.path.realpath(os.path.join(self.base_dir, storage_key))
        if not target_path.startswith(self.base_dir + os.sep) and target_path != self.base_dir:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Path traversal violation detected."
            )
        return target_path

    def save_file(self, file_obj: BinaryIO, storage_key: str) -> int:
        file_path = self._resolve_safe_path(storage_key)
        total_bytes = 0
        with open(file_path, "wb") as f:
            while chunk := file_obj.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > settings.MAX_FILE_SIZE_BYTES:
                    # Cleanup incomplete file on size violation
                    f.close()
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_BYTES / (1024*1024):.0f} MB"
                    )
                f.write(chunk)
        return total_bytes

    def read_file_stream(self, storage_key: str, chunk_size: int = 64 * 1024) -> Generator[bytes, None, None]:
        file_path = self._resolve_safe_path(storage_key)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content not found.")
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                yield chunk

    def delete_file(self, storage_key: str) -> bool:
        try:
            file_path = self._resolve_safe_path(storage_key)
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
            return False
        except Exception:
            return False

    def exists(self, storage_key: str) -> bool:
        file_path = self._resolve_safe_path(storage_key)
        return os.path.exists(file_path)

    def compute_checksum(self, storage_key: str) -> str:
        """
        Computes SHA-256 digest of stored bytes on disk to verify data integrity against corruption.
        """
        import hashlib
        file_path = self._resolve_safe_path(storage_key)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content not found.")
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

if settings.STORAGE_BACKEND == "s3" or (settings.S3_BUCKET_NAME and settings.S3_ACCESS_KEY_ID):
    from app.storage.s3 import S3StorageAdapter
    storage_service = S3StorageAdapter()
else:
    storage_service = LocalPrivateStorage()

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes user-provided filename, stripping dangerous directory traversal or control characters.
    Handles cross-platform path separators and double-dot traversal patterns safely.
    """
    # Normalize backslashes to forward slashes across all platforms (Linux/Windows)
    clean = filename.replace("\\", "/")
    clean = os.path.basename(clean)
    clean = re.sub(r'[\\/*?:"<>|\x00-\x1f]', "", clean)
    clean = re.sub(r'\.{2,}', "", clean)  # strip .. path traversal
    clean = clean.strip(". ")
    return clean if clean else "document.bin"

def validate_file_content(header_bytes: bytes, extension: str, content_type: str) -> None:
    """
    Validates file extension, MIME type, and magic bytes where applicable.
    """
    ext = extension.lower().lstrip(".")
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '.{ext}' is not permitted."
        )

    # Check magic bytes for known binary types
    if ext in FILE_SIGNATURES:
        signatures = FILE_SIGNATURES[ext]
        if not any(header_bytes.startswith(sig) for sig in signatures):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File content does not match expected format for .{ext}"
            )
