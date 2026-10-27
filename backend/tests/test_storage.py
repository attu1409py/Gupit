"""Unit tests for the storage abstraction and LocalFileSystemStorage driver."""

import tempfile
import pytest
from pathlib import Path
from backend.app.services.file_storage import (
    LocalFileSystemStorage,
    StorageNotFoundError,
)


def test_local_file_storage_lifecycle():
    """Test saving, retrieving, checking existence, and deleting packages."""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage = LocalFileSystemStorage(base_directory=temp_dir)
        package_id = "pkg_test_12345"
        payload = b"ENCRYPTED_PACKAGE_BINARY_DATA"

        # 1. Initially does not exist
        assert not storage.exists(package_id)

        # 2. Save package
        stored_path = storage.save_package(package_id, payload)
        assert Path(stored_path).exists()
        assert storage.exists(package_id)

        # 3. Retrieve package
        retrieved_data = storage.get_package(package_id)
        assert retrieved_data == payload

        # 4. Delete package
        deleted = storage.delete_package(package_id)
        assert deleted is True
        assert not storage.exists(package_id)

        # 5. Access after delete raises StorageNotFoundError
        with pytest.raises(StorageNotFoundError):
            storage.get_package(package_id)
