import pytest
from app.core.config import settings
from app.storage.local import init_storage_service, LocalPrivateStorage

def test_s3_storage_fails_fast_without_silent_fallback(monkeypatch):
    """
    Verifies that when STORAGE_BACKEND is 's3' but credentials are missing,
    the application fails fast with RuntimeError instead of silently falling back to local storage.
    """
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "s3")
    monkeypatch.setattr(settings, "S3_BUCKET_NAME", None)
    monkeypatch.setattr(settings, "S3_ACCESS_KEY_ID", None)
    monkeypatch.setattr(settings, "S3_SECRET_ACCESS_KEY", None)

    with pytest.raises(RuntimeError) as exc_info:
        init_storage_service()
    assert "Failing fast to prevent silent fallback" in str(exc_info.value)

def test_invalid_storage_backend_rejected(monkeypatch):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "unsupported_storage_provider")
    with pytest.raises(ValueError) as exc_info:
        init_storage_service()
    assert "Invalid STORAGE_BACKEND" in str(exc_info.value)

def test_local_storage_backend_selected(monkeypatch):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "local")
    service = init_storage_service()
    assert isinstance(service, LocalPrivateStorage)

def test_health_reports_storage_backend_and_dependencies(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "storage_backend" in data
    assert data["dependencies"]["database"] == "connected"
    assert data["dependencies"]["storage"] == "connected"
