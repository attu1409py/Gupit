"""Storage abstraction layer and Local Filesystem driver for encrypted packages."""

from abc import ABC, abstractmethod
import os
from pathlib import Path
from typing import BinaryIO, Optional


class StorageError(Exception):
    """Base exception for storage errors."""
    pass


class StorageNotFoundError(StorageError):
    """Raised when the requested package cannot be found in storage."""
    pass


class BaseStorageService(ABC):
    """Abstract interface for package persistence, enabling future object storage (e.g. S3)."""

    @abstractmethod
    def save_package(self, package_id: str, data: bytes) -> str:
        """Save encrypted package data and return its persistent reference or path.

        Args:
            package_id: Unique package identifier.
            data: Binary package content.

        Returns:
            String storage identifier/path.
        """
        pass

    @abstractmethod
    def get_package(self, package_id: str) -> bytes:
        """Retrieve package bytes by identifier.

        Args:
            package_id: Unique package identifier.

        Returns:
            Raw package bytes.

        Raises:
            StorageNotFoundError: If package does not exist.
        """
        pass

    @abstractmethod
    def delete_package(self, package_id: str) -> bool:
        """Delete package bytes by identifier.

        Args:
            package_id: Unique package identifier.

        Returns:
            True if deleted, False if not found.
        """
        pass

    @abstractmethod
    def exists(self, package_id: str) -> bool:
        """Check if package exists in storage."""
        pass


class LocalFileSystemStorage(BaseStorageService):
    """Local filesystem implementation of BaseStorageService for development and testing."""

    def __init__(self, base_directory: str = "./storage/packages"):
        self.base_dir = Path(base_directory).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, package_id: str) -> Path:
        safe_name = f"{package_id}.pkg"
        return self.base_dir / safe_name

    def save_package(self, package_id: str, data: bytes) -> str:
        file_path = self._get_path(package_id)
        with open(file_path, "wb") as f:
            f.write(data)
        return str(file_path)

    def get_package(self, package_id: str) -> bytes:
        file_path = self._get_path(package_id)
        if not file_path.is_file():
            raise StorageNotFoundError(f"Package '{package_id}' not found in local storage.")
        with open(file_path, "rb") as f:
            return f.read()

    def delete_package(self, package_id: str) -> bool:
        file_path = self._get_path(package_id)
        if file_path.is_file():
            file_path.unlink()
            return True
        return False

    def exists(self, package_id: str) -> bool:
        return self._get_path(package_id).is_file()
