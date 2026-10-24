"""Phase 9 Test Suite: External Security Posture, Headers, Cookies, CORS, and Body Limits.
Validates:
1. Automated header scanner verifying all required security headers across routes.
2. CORS strict origin allowlist, rejection of null and arbitrary origins, zero reflection.
3. Tiered rate limiting (Auth 5/min IP & username, Downloads 10/min) triggering 429 and Retry-After.
4. Request body limits (50 MB upload, 1 MB JSON) rejecting oversized payloads with 413.
5. Cookie security: __Host- prefix, Secure, HttpOnly, SameSite=Strict, Path=/.
6. Cloudflare perimeter lockdown and direct-to-origin defense.
"""

import io
import time
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.tests.conftest import get_auth_headers
from app.models.user import User
from app.core.config import settings
from app.core.rate_limit import (
    auth_ip_limiter,
    auth_user_limiter,
    content_download_limiter,
    policy_simulator_limiter
)


def test_security_headers_scanner_across_routes(client: TestClient, test_users):
    """
    Phase 9 Requirement:
    Automated header scanner verifying all required security headers across routes:
    - HSTS (includeSubDomains and preload)
    - X-Content-Type-Options: nosniff
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()
    - Cross-Origin-Embedder-Policy: require-corp
    - Cross-Origin-Opener-Policy: same-origin
    - Cross-Origin-Resource-Policy: same-origin
    - X-Frame-Options: DENY
    - Content-Security-Policy: frame-ancestors 'none'
    - Cache-Control: no-store, private on API routes
    """
    routes_to_scan = [
        ("/", {}),
        ("/api/v1/health", {}),
        ("/api/v1/documents", get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!"))
    ]

    for path, headers in routes_to_scan:
        res = client.get(path, headers=headers)
        h = res.headers

        # 1. HSTS
        assert "strict-transport-security" in h, f"Missing HSTS on {path}"
        assert "max-age=63072000" in h["strict-transport-security"]
        assert "includeSubDomains" in h["strict-transport-security"]
        assert "preload" in h["strict-transport-security"]

        # 2. Sniffing & Framing
        assert h.get("x-content-type-options") == "nosniff", f"Missing nosniff on {path}"
        assert h.get("x-frame-options") == "DENY", f"Missing DENY on {path}"

        # 3. Referrer & Permissions
        assert h.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert h.get("permissions-policy") == "camera=(), microphone=(), geolocation=(), usb=(), payment=()"

        # 4. Cross-Origin Posture
        assert h.get("cross-origin-embedder-policy") == "require-corp"
        assert h.get("cross-origin-opener-policy") == "same-origin"
        assert h.get("cross-origin-resource-policy") == "same-origin"

        # 5. Content Security Policy
        assert "content-security-policy" in h
        assert "frame-ancestors 'none'" in h["content-security-policy"]

        # 6. Zero-cache on API routes
        if path.startswith("/api/"):
            assert h.get("cache-control") == "no-store, private"
            assert h.get("pragma") == "no-cache"


def test_cors_strict_origin_allowlist_and_no_reflection(client: TestClient):
    """
    Phase 9 Requirement:
    - Strict origin allowlist from env
    - NO reflection of arbitrary origins
    - Access-Control-Allow-Credentials: true ONLY when origin is explicitly allowed
    - Reject null origin
    - Preflight cache max-age capped
    """
    # 1. Arbitrary attacker origin -> NOT reflected
    evil_res = client.get(
        "/api/v1/health",
        headers={"Origin": "https://malicious-attacker.com"}
    )
    assert evil_res.headers.get("access-control-allow-origin") is None
    assert evil_res.headers.get("access-control-allow-credentials") is None

    # 2. Null origin -> NOT reflected
    null_res = client.get(
        "/api/v1/health",
        headers={"Origin": "null"}
    )
    assert null_res.headers.get("access-control-allow-origin") is None
    assert null_res.headers.get("access-control-allow-credentials") is None

    # 3. Preflight OPTIONS from arbitrary origin -> rejected without allow-origin
    preflight_evil = client.options(
        "/api/v1/health",
        headers={
            "Origin": "https://malicious-attacker.com",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert preflight_evil.headers.get("access-control-allow-origin") is None

    # 4. Valid configured origin (localhost:5173) -> ALLOWED with credentials
    valid_origin = "http://localhost:5173"
    valid_res = client.get(
        "/api/v1/health",
        headers={"Origin": valid_origin}
    )
    assert valid_res.headers.get("access-control-allow-origin") == valid_origin
    assert valid_res.headers.get("access-control-allow-credentials") == "true"

    # 5. Preflight cache max-age capped
    preflight_valid = client.options(
        "/api/v1/health",
        headers={
            "Origin": valid_origin,
            "Access-Control-Request-Method": "GET"
        }
    )
    assert preflight_valid.headers.get("access-control-allow-origin") == valid_origin
    assert preflight_valid.headers.get("access-control-max-age") == "600"


def test_rate_limiting_auth_endpoints_ip_and_username(client: TestClient):
    """
    Phase 9 Requirement:
    Auth endpoints: 5/min per IP, 5/min per username (account-lockout defense).
    Returns 429 with 'Retry-After'.
    """
    auth_ip_limiter.reset()
    auth_user_limiter.reset()

    # 1. Test IP Rate Limiting: 5 attempts allowed, 6th triggers 429
    for i in range(5):
        res = client.post(
            "/api/v1/auth/login",
            json={"email": f"diff_user_{i}@test.com", "password": "WrongPassword123!"},
            headers={"X-Forwarded-For": "198.51.100.55"}
        )
        assert res.status_code == 401, f"Attempt {i+1} failed with {res.status_code}"

    # 6th attempt from same IP -> 429 Too Many Requests
    blocked_res = client.post(
        "/api/v1/auth/login",
        json={"email": "diff_user_99@test.com", "password": "WrongPassword123!"},
        headers={"X-Forwarded-For": "198.51.100.55"}
    )
    assert blocked_res.status_code == 429
    assert "Retry-After" in blocked_res.headers
    retry_after = int(blocked_res.headers["Retry-After"])
    assert 1 <= retry_after <= 60

    # 2. Test Username Rate Limiting: different IPs targeting the SAME username
    auth_ip_limiter.reset()
    auth_user_limiter.reset()
    target_victim = "targeted_account@test.com"

    for i in range(5):
        res = client.post(
            "/api/v1/auth/login",
            json={"email": target_victim, "password": "WrongPassword123!"},
            headers={"X-Forwarded-For": f"198.51.100.{100 + i}"}  # distinct IP each time
        )
        assert res.status_code == 401

    # 6th attempt on the target username from a fresh IP -> blocked by username limiter
    blocked_user_res = client.post(
        "/api/v1/auth/login",
        json={"email": target_victim, "password": "WrongPassword123!"},
        headers={"X-Forwarded-For": "198.51.100.250"}
    )
    assert blocked_user_res.status_code == 429
    assert "Retry-After" in blocked_user_res.headers


def test_rate_limiting_content_downloads(client: TestClient, test_users, test_db_session: Session):
    """
    Phase 9 Requirement:
    Content endpoints: strict bursts (10/min for downloads).
    Returns 429 with 'Retry-After'.
    """
    content_download_limiter.reset()
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # Upload test document
    files = {"file": ("rate_test.txt", io.BytesIO(b"Rate limit download test content"), "text/plain")}
    up_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Rate Limit Doc", "category": "General"},
        files=files
    )
    assert up_res.status_code == 201
    doc_id = up_res.json()["id"]

    # Perform 10 rapid downloads -> all permitted
    for i in range(10):
        dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
        assert dl_res.status_code == 200, f"Download {i+1} failed"

    # 11th download attempt -> 429 Too Many Requests
    blocked_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
    assert blocked_dl.status_code == 429
    assert "Retry-After" in blocked_dl.headers
    retry_sec = int(blocked_dl.headers["Retry-After"])
    assert 1 <= retry_sec <= 60


def test_request_body_size_limits_rejection(client: TestClient, test_users):
    """
    Phase 9 Requirement:
    Request body limits: hard cap 50 MB for file uploads, 1 MB for JSON API payloads.
    Reject oversized payloads BEFORE buffering to disk or memory (returns 413).
    """
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # 1. JSON endpoint with Content-Length exceeding 1 MB limit
    oversized_json_len = 2 * 1024 * 1024  # 2 MB
    res_json = client.post(
        "/api/v1/documents",
        headers={**headers, "Content-Length": str(oversized_json_len)},
        content=b'{"test": "payload"}'
    )
    assert res_json.status_code == 413
    assert "Request entity too large" in res_json.json()["detail"]

    # 2. Upload endpoint with Content-Length exceeding 50 MB limit
    oversized_upload_len = 55 * 1024 * 1024  # 55 MB
    res_upload = client.post(
        "/api/v1/documents/upload",
        headers={**headers, "Content-Length": str(oversized_upload_len)},
        content=b"dummy"
    )
    assert res_upload.status_code == 413
    assert "Request entity too large" in res_upload.json()["detail"]


def test_session_cookie_host_prefix_and_security(client: TestClient, test_users):
    """
    Phase 9 Requirement:
    Cookie security: __Host- prefix on all session cookies, Secure, HttpOnly, SameSite=Strict, path=/.
    """
    auth_ip_limiter.reset()
    auth_user_limiter.reset()

    # 1. Login sets the __Host- prefixed session cookie
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "owner_a@test.com", "password": "OwnerAPass123!"}
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    cookie_header = login_res.headers.get("set-cookie")
    assert cookie_header is not None
    assert "__Host-trustvault_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header
    assert "SameSite=Strict" in cookie_header or "samesite=strict" in cookie_header.lower()
    assert "Path=/" in cookie_header or "path=/" in cookie_header.lower()
    # RFC 6265bis: __Host- cookies MUST NOT specify a Domain attribute
    assert "Domain=" not in cookie_header

    # 2. Authenticate using the __Host- session cookie (without Bearer header)
    cookie_auth_res = client.get(
        "/api/v1/auth/me",
        cookies={"__Host-trustvault_session": token}
    )
    assert cookie_auth_res.status_code == 200
    assert cookie_auth_res.json()["email"] == "owner_a@test.com"

    # 3. Logout clears the cookie
    logout_res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_res.status_code == 200
    del_cookie = logout_res.headers.get("set-cookie")
    assert del_cookie is not None
    assert "__Host-trustvault_session=" in del_cookie


def test_cloudflare_direct_to_origin_lockdown(client: TestClient):
    """
    Phase 9 Requirement:
    Block direct-to-origin traffic when ENFORCE_CLOUDFLARE_ORIGIN is enabled.
    Origin accepts only Cloudflare traffic with CF-Ray and CF-Connecting-IP.
    """
    original_setting = settings.ENFORCE_CLOUDFLARE_ORIGIN
    try:
        # Enable enforcement
        settings.ENFORCE_CLOUDFLARE_ORIGIN = True

        # 1. Direct request without Cloudflare headers -> 403 Forbidden
        direct_res = client.get("/api/v1/health")
        assert direct_res.status_code == 403
        assert "Direct-to-origin access is forbidden" in direct_res.json()["detail"]

        # 2. Transit via Cloudflare with edge headers -> 200 OK
        cf_res = client.get(
            "/api/v1/health",
            headers={
                "CF-Ray": "890123abcdef-IAD",
                "CF-Connecting-IP": "203.0.113.19"
            }
        )
        assert cf_res.status_code == 200
    finally:
        settings.ENFORCE_CLOUDFLARE_ORIGIN = original_setting
