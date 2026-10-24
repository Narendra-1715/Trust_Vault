import os
import shutil
import tempfile
import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from hypothesis import settings as hyp_settings, Verbosity, HealthCheck

from app.main import app
from app.core.config import settings
from app.db.session import Base, get_db
from app.core.security import hash_password
from app.core.rate_limit import login_limiter, upload_limiter, ai_limiter, access_request_limiter
from app.models.user import User
from app.storage.local import LocalPrivateStorage, storage_service

# Register Hypothesis profiles for property-based security testing
hyp_settings.register_profile("ci", max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
hyp_settings.register_profile("dev", max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
hyp_settings.register_profile("debug", max_examples=10, verbosity=Verbosity.verbose, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
hyp_settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))

@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """Resets rate limiters and enforces deterministic mock AI before each test."""
    settings.AI_PROVIDER = "mock"
    login_limiter.reset()
    upload_limiter.reset()
    ai_limiter.reset()
    access_request_limiter.reset()

@pytest.fixture(scope="session")
def test_temp_dir():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture(scope="function")
def test_db_session(test_temp_dir):
    """
    Creates isolated test database per test function.
    Uses PostgreSQL container if TEST_DATABASE_URL is provided,
    otherwise creates a temporary isolated SQLite database.
    """
    pg_url = os.getenv("TEST_DATABASE_URL")
    if pg_url:
        from sqlalchemy import text
        engine = create_engine(pg_url, pool_pre_ping=True)
        Base.metadata.create_all(bind=engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.rollback()
            session.close()
            with engine.connect() as conn:
                conn.execute(text("DROP VIEW IF EXISTS ai_document_metadata_view CASCADE;"))
                for table in reversed(Base.metadata.sorted_tables):
                    conn.execute(text(f'DROP TABLE IF EXISTS "{table.name}" CASCADE;'))
                conn.commit()
            engine.dispose()
    else:
        db_file = os.path.join(test_temp_dir, f"test_{os.urandom(4).hex()}.db")
        engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
        
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        Base.metadata.create_all(bind=engine)

        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()
            Base.metadata.drop_all(bind=engine)
            if os.path.exists(db_file):
                try:
                    os.remove(db_file)
                except OSError:
                    pass

@pytest.fixture(scope="function")
def test_storage(test_temp_dir):
    """Isolated temporary storage adapter for tests."""
    storage_path = os.path.join(test_temp_dir, f"storage_{os.urandom(4).hex()}")
    adapter = LocalPrivateStorage(base_dir=storage_path)
    # Monkey-patch storage_service
    orig_base = storage_service.base_dir
    storage_service.base_dir = adapter.base_dir
    yield adapter
    storage_service.base_dir = orig_base
    shutil.rmtree(storage_path, ignore_errors=True)

@pytest.fixture(scope="function", autouse=True)
def reset_rate_limiters():
    """Resets in-memory sliding-window rate limiters before each test."""
    from app.core.rate_limit import (
        auth_ip_limiter,
        auth_user_limiter,
        content_download_limiter,
        policy_simulator_limiter,
        upload_limiter,
        access_request_limiter,
        ai_limiter
    )
    auth_ip_limiter.reset()
    auth_user_limiter.reset()
    content_download_limiter.reset()
    policy_simulator_limiter.reset()
    upload_limiter.reset()
    access_request_limiter.reset()
    ai_limiter.reset()
    yield

@pytest.fixture(scope="function")
def client(test_db_session, test_storage):
    """FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            if not test_db_session.is_active:
                test_db_session.rollback()
        except Exception:
            pass
        try:
            yield test_db_session
        except Exception:
            try:
                test_db_session.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                if not test_db_session.is_active:
                    test_db_session.rollback()
            except Exception:
                pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def test_users(test_db_session):
    """Seeds predictable test users for auth & authz testing."""
    admin = User(
        email="admin@test.com",
        password_hash=hash_password("AdminPass123!"),
        display_name="Test Admin",
        role="admin",
        is_active=True
    )
    owner_a = User(
        email="owner_a@test.com",
        password_hash=hash_password("OwnerAPass123!"),
        display_name="Owner Alice",
        role="owner",
        is_active=True
    )
    owner_b = User(
        email="owner_b@test.com",
        password_hash=hash_password("OwnerBPass123!"),
        display_name="Owner Bob",
        role="owner",
        is_active=True
    )
    viewer_a = User(
        email="viewer_a@test.com",
        password_hash=hash_password("ViewerAPass123!"),
        display_name="Viewer Charlie",
        role="viewer",
        is_active=True
    )
    disabled_user = User(
        email="disabled@test.com",
        password_hash=hash_password("DisabledPass123!"),
        display_name="Disabled Dave",
        role="viewer",
        is_active=False
    )

    test_db_session.add_all([admin, owner_a, owner_b, viewer_a, disabled_user])
    test_db_session.commit()
    return {
        "admin": admin,
        "owner_a": owner_a,
        "owner_b": owner_b,
        "viewer_a": viewer_a,
        "disabled": disabled_user
    }

def get_auth_headers(client: TestClient, email: str, password: str) -> dict:
    """Helper to authenticate and return Bearer header."""
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, f"Login failed for {email}: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
