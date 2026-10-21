from abc import ABC, abstractmethod
from typing import BinaryIO, Generator

class BaseStorageAdapter(ABC):
    """
    Abstract interface for private document object storage.
    """

    @abstractmethod
    def save_file(self, file_obj: BinaryIO, storage_key: str) -> int:
        """Saves file to private storage, returning total byte count."""
        pass

    @abstractmethod
    def read_file_stream(self, storage_key: str, chunk_size: int = 64 * 1024) -> Generator[bytes, None, None]:
        """Streams file bytes from private storage."""
        pass

    @abstractmethod
    def delete_file(self, storage_key: str) -> bool:
        """Removes file from private storage."""
        pass

    @abstractmethod
    def exists(self, storage_key: str) -> bool:
        """Checks if file exists in private storage."""
        pass
