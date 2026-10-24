"""Phase 11 Test Suite: Security Observability, SIEM Exports, Webhooks & Incident Response.
Validates:
1. Structured JSON logging with automated credential redaction and contextvars correlation.
2. SIEM export in CEF, ECS (NDJSON), and RFC 5424 Syslog formats.
3. Outbound security webhook dispatch with HMAC-SHA256 signatures, timestamps, and Invariant I1/I4 data hygiene.
4. Webhook rate-limiting and alert storm suppression.
5. Cryptographic audit ledger tampering triggers an active CRITICAL SecurityAlert.
6. Correlation middleware attaches X-Request-ID and X-Correlation-ID to responses.
"""

import io
import json
import logging
import time
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
import httpx

from app.models.user import User
from app.models.audit import AuditEvent
from app.models.security_alert import SecurityAlert
from app.core.config import settings
from app.core.logging import (
    StructuredJSONFormatter,
    SensitiveDataFilter,
    request_id_ctx,
    correlation_id_ctx,
    actor_id_ctx,
    client_ip_ctx,
    redact_sensitive_value
)
from app.audit.siem import (
    format_event_cef,
    format_event_ecs,
    format_event_syslog,
    escape_cef_value
)
from app.services.webhook import (
    compute_webhook_signature,
    verify_webhook_signature,
    build_safe_alert_payload,
    dispatch_security_webhook,
    WebhookRateLimiter
)
from app.audit.verifier import verify_audit_integrity
from app.tests.conftest import get_auth_headers


def test_structured_json_logging_and_credential_redaction():
    """
    Phase 11 Requirement:
    Structured JSON logs must emit ISO 8601 timestamps, context correlation IDs,
    and automatically redact credentials, tokens, and encryption keys.
    """
    formatter = StructuredJSONFormatter()
    log_filter = SensitiveDataFilter()

    # Set asynchronous tracing context
    req_token = request_id_ctx.set("req-test-uuid-1234")
    corr_token = correlation_id_ctx.set("corr-trace-5678")
    actor_token = actor_id_ctx.set("user-actor-999")
    ip_token = client_ip_ctx.set("198.51.100.42")

    try:
        record = logging.LogRecord(
            name="trustvault.auth",
            level=logging.INFO,
            pathname=__file__,
            lineno=42,
            msg="User login attempt with token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature",
            args=(),
            exc_info=None
        )
        # Attach extra metadata containing sensitive keys
        record.password = "SuperSecretPassword123!"
        record.encryption_key = "0123456789abcdef0123456789abcdef"
        record.safe_param = "public_identifier"

        log_filter.filter(record)
        formatted_json = formatter.format(record)
        data = json.loads(formatted_json)

        # 1. Structure & Correlation
        assert data["service"] == "trustvault-backend"
        assert data["level"] == "INFO"
        assert data["request_id"] == "req-test-uuid-1234"
        assert data["correlation_id"] == "corr-trace-5678"
        assert data["actor_id"] == "user-actor-999"
        assert data["client_ip"] == "198.51.100.42"

        # 2. Message Redaction
        assert "Bearer [REDACTED]" in data["message"]
        assert "eyJhbGci" not in data["message"]

        # 3. Attribute Redaction
        extras = data.get("extra", {})
        assert extras.get("password") == "[REDACTED]"
        assert extras.get("encryption_key") == "[REDACTED]"
        assert extras.get("safe_param") == "public_identifier"
    finally:
        request_id_ctx.reset(req_token)
        correlation_id_ctx.reset(corr_token)
        actor_id_ctx.reset(actor_token)
        client_ip_ctx.reset(ip_token)


def test_siem_export_formats_cef_ecs_syslog(client: TestClient, test_users, test_db_session: Session):
    """
    Phase 11 Requirement:
    SIEM exports must support CEF (ArcSight), ECS (Elastic NDJSON), and RFC 5424 Syslog
    with correct headers, MIME types, and cryptographic hashes.
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    # 1. CEF Export
    cef_res = client.get("/api/v1/audit/export?format=cef", headers=admin_headers)
    assert cef_res.status_code == 200
    assert cef_res.headers["content-type"].startswith("text/plain")
    assert "attachment; filename=" in cef_res.headers["content-disposition"]
    assert cef_res.headers["content-disposition"].endswith('.cef"')
    cef_text = cef_res.text
    assert "CEF:0|TrustVault|TrustVault-Enterprise|1.0|" in cef_text
    assert "cs1Label=RequestId" in cef_text
    assert "cs4Label=EventHash" in cef_text

    # 2. ECS Export (Elastic Common Schema NDJSON)
    ecs_res = client.get("/api/v1/audit/export?format=ecs", headers=admin_headers)
    assert ecs_res.status_code == 200
    assert "application/x-ndjson" in ecs_res.headers["content-type"]
    assert ecs_res.headers["content-disposition"].endswith('.ecs.ndjson"')
    lines = [line.strip() for line in ecs_res.text.strip().split("\n") if line.strip()]
    assert len(lines) > 0
    # Parse first line as ECS JSON
    doc = json.loads(lines[0])
    assert "@timestamp" in doc
    assert doc["ecs"]["version"] == "8.11.0"
    assert "event" in doc
    assert "action" in doc["event"]
    assert "trustvault" in doc
    assert "event_hash" in doc["trustvault"]

    # 3. RFC 5424 Syslog Export
    syslog_res = client.get("/api/v1/audit/export?format=syslog", headers=admin_headers)
    assert syslog_res.status_code == 200
    assert syslog_res.headers["content-type"].startswith("text/plain")
    assert syslog_res.headers["content-disposition"].endswith('.syslog"')
    syslog_text = syslog_res.text
    assert "<13" in syslog_text  # PRI code (<131> or <134>)
    assert "trustvault-node api - audit [trustvault@41123" in syslog_text


def test_outbound_security_webhook_signature_and_data_hygiene():
    """
    Phase 11 Requirement:
    Webhooks must compute valid HMAC-SHA256 signatures, include timestamps,
    and enforce Invariant I1/I4 data hygiene (no document titles, plaintext, or keys).
    """
    secret = "test-webhook-signing-secret-key-32b"
    test_alert = SecurityAlert(
        id="alert-uuid-1111",
        event_type="brute_force_login",
        severity="high",
        status="open",
        timestamp=datetime.now(timezone.utc),
        actor_id="actor-uuid-2222",
        target_user_id="victim-uuid-3333",
        target_document_id="doc-secret-4444",
        request_id="req-5555",
        summary="Excessive failed logins against target account",
        investigation_metadata={
            "ip_address": "203.0.113.15",
            "document_title": "Top Secret M&A Strategy.pdf",  # Must be redacted!
            "password": "AttemptedPassword!",                 # Must be redacted!
            "failed_attempts": 5
        }
    )

    # 1. Verify Invariant I1 & I4 Data Hygiene in Payload
    payload = build_safe_alert_payload(test_alert)
    assert payload["id"] == "alert-uuid-1111"
    assert payload["event_type"] == "brute_force_login"
    assert payload["investigation_metadata"]["failed_attempts"] == 5
    # Strict Redaction Checks
    assert payload["investigation_metadata"]["document_title"] == "[REDACTED]"
    assert payload["investigation_metadata"]["password"] == "[REDACTED]"
    assert "Top Secret M&A" not in json.dumps(payload)

    # 2. Mock Transport to verify signature and headers
    dispatched_requests = []

    def mock_handler(request: httpx.Request):
        dispatched_requests.append(request)
        return httpx.Response(200, json={"status": "received"})

    mock_client = httpx.Client(transport=httpx.MockTransport(mock_handler))

    ok, msg = dispatch_security_webhook(
        alert=test_alert,
        webhook_url="https://siem.test.local/webhooks/security",
        webhook_secret=secret,
        client=mock_client
    )
    assert ok is True
    assert len(dispatched_requests) == 1

    req = dispatched_requests[0]
    headers = req.headers
    assert "x-trustvault-signature" in headers
    assert "x-trustvault-timestamp" in headers
    assert headers["x-trustvault-event"] == "brute_force_login"

    # 3. Verify HMAC-SHA256 Signature mathematically
    timestamp = headers["x-trustvault-timestamp"]
    sig_header = headers["x-trustvault-signature"]
    sign_data = timestamp.encode("utf-8") + b"." + req.content
    assert verify_webhook_signature(sign_data, secret, sig_header) is True


def test_security_webhook_rate_limiting_flood_prevention():
    """
    Phase 11 Requirement:
    Rate limiting prevents webhook storm exhaustion against recipient SIEM endpoints.
    """
    limiter = WebhookRateLimiter(max_per_minute=3)
    endpoint = "https://siem.example.com/alerts"

    assert limiter.is_allowed(endpoint) is True
    assert limiter.is_allowed(endpoint) is True
    assert limiter.is_allowed(endpoint) is True
    # 4th request within 1 minute must be blocked
    assert limiter.is_allowed(endpoint) is False


def test_audit_ledger_tampering_triggers_critical_alert(test_db_session: Session):
    """
    Phase 11 Requirement:
    Cryptographic audit ledger tampering (sequence gap, bit modification, or chain severance)
    automatically raises a CRITICAL SecurityAlert.
    """
    # 1. Create 3 valid chained audit events
    from app.audit.service import log_audit_event
    log_audit_event(
        db=test_db_session,
        action="test.event.one",
        resource_type="document",
        resource_id="doc_1",
        outcome="success",
        actor_id=None,
        request_id="req_1"
    )
    log_audit_event(
        db=test_db_session,
        action="test.event.two",
        resource_type="document",
        resource_id="doc_2",
        outcome="success",
        actor_id=None,
        request_id="req_2"
    )
    e3 = log_audit_event(
        db=test_db_session,
        action="test.event.three",
        resource_type="document",
        resource_id="doc_3",
        outcome="success",
        actor_id=None,
        request_id="req_3"
    )

    # Clean verification passes initially
    clean_check = verify_audit_integrity(test_db_session)
    assert clean_check["is_valid"] is True

    # 2. Corrupt event 3's hash (simulating malicious DB tampering)
    e3_db = test_db_session.query(AuditEvent).filter(AuditEvent.id == e3.id).first()
    e3_db.event_hash = "0" * 64
    test_db_session.commit()

    # 3. Verification now fails AND triggers a CRITICAL alert
    tamper_check = verify_audit_integrity(test_db_session)
    assert tamper_check["is_valid"] is False
    assert tamper_check["tampered_event_id"] == e3.id

    # 4. Confirm a critical security alert was recorded
    alert = (
        test_db_session.query(SecurityAlert)
        .filter(SecurityAlert.event_type == "audit_ledger_tampered")
        .order_by(SecurityAlert.timestamp.desc())
        .first()
    )
    assert alert is not None
    assert alert.severity == "critical"
    assert alert.status == "open"
    assert e3.id in alert.summary or str(alert.investigation_metadata).find(e3.id) != -1


def test_correlation_middleware_attaches_request_and_correlation_ids(client: TestClient):
    """
    Phase 11 Requirement:
    Correlation middleware attaches X-Request-ID and X-Correlation-ID to responses.
    """
    custom_req_id = "req-custom-trace-12345"
    custom_corr_id = "corr-custom-trace-67890"

    res = client.get(
        "/api/v1/health",
        headers={
            "X-Request-ID": custom_req_id,
            "X-Correlation-ID": custom_corr_id
        }
    )
    assert res.status_code == 200
    assert res.headers.get("x-request-id") == custom_req_id
    assert res.headers.get("x-correlation-id") == custom_corr_id
