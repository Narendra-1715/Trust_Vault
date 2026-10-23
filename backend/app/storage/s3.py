import os
import hashlib
from typing import BinaryIO, Generator
from fastapi import HTTPException, status
from app.core.config import settings
from app.storage.base import BaseStorageAdapter

class S3StorageAdapter(BaseStorageAdapter):
    """
    S3-compatible private object storage adapter for Supabase Storage, Cloudflare R2, AWS S3, and MinIO.
    Stores confidential files in private encrypted buckets with opaque UUID keys.
    """

    def __init__(
        self,
        endpoint_url: str = settings.S3_ENDPOINT_URL,
        bucket_name: str = settings.S3_BUCKET_NAME,
        access_key: str = settings.S3_ACCESS_KEY_ID,
        secret_key: str = settings.S3_SECRET_ACCESS_KEY,
        region_name: str = settings.S3_REGION_NAME or "us-east-1",
    ):
        import boto3
        from botocore.config import Config

        if not bucket_name:
            raise ValueError("S3_BUCKET_NAME must be specified for S3StorageAdapter.")

        self.bucket = bucket_name
        self.endpoint_url = endpoint_url
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region_name,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    def _validate_key(self, storage_key: str):
        if not storage_key or ".." in storage_key or "/" in storage_key or "\\" in storage_key or "\0" in storage_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid storage key detected."
            )

    def save_file(self, file_obj: BinaryIO, storage_key: str) -> int:
        self._validate_key(storage_key)
        total_bytes = 0
        chunks = []
        while chunk := file_obj.read(64 * 1024):
            total_bytes += len(chunk)
            if total_bytes > settings.MAX_FILE_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_BYTES / (1024*1024):.0f} MB"
                )
            chunks.append(chunk)

        body_bytes = b"".join(chunks)
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=storage_key,
                Body=body_bytes,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to persist file to private object storage: {str(e)}"
            )
        return total_bytes

    def read_file_stream(self, storage_key: str, chunk_size: int = 64 * 1024) -> Generator[bytes, None, None]:
        self._validate_key(storage_key)
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=storage_key)
            body = response["Body"]
            while chunk := body.read(chunk_size):
                yield chunk
        except Exception as e:
            error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "404") or "NoSuchKey" in str(e):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content not found.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Storage error reading object: {str(e)}"
            )

    def delete_file(self, storage_key: str) -> bool:
        self._validate_key(storage_key)
        try:
            self.client.delete_object(Bucket=self.bucket, Key=storage_key)
            return True
        except Exception:
            return False

    def exists(self, storage_key: str) -> bool:
        self._validate_key(storage_key)
        try:
            self.client.head_object(Bucket=self.bucket, Key=storage_key)
            return True
        except Exception:
            return False

    def compute_checksum(self, storage_key: str) -> str:
        self._validate_key(storage_key)
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=storage_key)
            body = response["Body"]
            hasher = hashlib.sha256()
            while chunk := body.read(64 * 1024):
                hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content not found.")
