import io
import pytest
from unittest.mock import MagicMock
from app.storage.s3 import S3StorageAdapter

def test_s3_storage_adapter_save_read_delete():
    # Mock boto3 client
    mock_boto = MagicMock()
    mock_body = MagicMock()
    mock_body.read.side_effect = [b"Test file content", b""]
    mock_boto.get_object.return_value = {"Body": mock_body}
    mock_boto.head_object.return_value = {"ContentLength": 17}

    adapter = S3StorageAdapter.__new__(S3StorageAdapter)
    adapter.bucket = "test-bucket"
    adapter.client = mock_boto

    # 1. Test Save
    data = io.BytesIO(b"Hello secure S3 storage")
    bytes_saved = adapter.save_file(data, "safe-uuid-key")
    assert bytes_saved == 23
    mock_boto.put_object.assert_called_once()

    # 2. Test Exists
    assert adapter.exists("safe-uuid-key") is True
    mock_boto.head_object.assert_called_with(Bucket="test-bucket", Key="safe-uuid-key")

    # 3. Test Read Stream
    stream = list(adapter.read_file_stream("safe-uuid-key"))
    assert b"".join(stream) == b"Test file content"

    # 4. Test Delete
    assert adapter.delete_file("safe-uuid-key") is True
    mock_boto.delete_object.assert_called_with(Bucket="test-bucket", Key="safe-uuid-key")
