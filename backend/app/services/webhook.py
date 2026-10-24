"""
Security Alert Webhook Dispatcher (Phase 11).
Enforces:
1. Outbound alert notifications for SIEMs and incident response endpoints.
2. Cryptographic HMAC-SHA256 signatures with replay protection timestamps.
3. Invariant I1 & I4 compliance: zero leakage of document titles, plaintext, or encryption keys.
4. Token bucket / sliding-window rate limiting to prevent webhook flooding during alert bursts.
5. Resilient retries with exponential backoff on transport errors.
"""

import hmac
import hashlib
import json
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List
from collections import defaultdict
import httpx

from app.core.config import settings
from app.models.security_alert import SecurityAlert
from app.core.logging import redact_sensitive_value

logger = logging.getLogger(__name__)


def compute_webhook_signature(payload_bytes: bytes, secret: str) -> str:
    """Computes HMAC-SHA256 signature for outbound webhook payload verification."""
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return mac.hexdigest()


def verify_webhook_signature(payload_bytes: bytes, secret: str, signature_header: str) -> bool:
    """
    Verifies HMAC-SHA256 signature in constant time.
    Expects header format: 'sha256=<hex_digest>' or raw hex digest.
    """
    if not signature_header or not secret:
        return False
    raw_sig = signature_header.strip()
    if raw_sig.startswith("sha256="):
        raw_sig = raw_sig[7:].strip()
    expected = compute_webhook_signature(payload_bytes, secret)
    return hmac.compare_digest(raw_sig, expected)


class WebhookRateLimiter:
    """Sliding-window limiter to prevent webhook flooding against recipient endpoints."""
    def __init__(self, max_per_minute: int = 10):
        self.max_per_minute = max_per_minute
        self.history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, endpoint_key: str) -> bool:
        now = time.time()
        cutoff = now - 60.0
        # Clean expired timestamps
        self.history[endpoint_key] = [ts for ts in self.history[endpoint_key] if ts > cutoff]
        if len(self.history[endpoint_key]) >= self.max_per_minute:
            return False
        self.history[endpoint_key].append(now)
        return True

    def reset(self):
        self.history.clear()


# Global limiter for security alert webhooks
webhook_limiter = WebhookRateLimiter(max_per_minute=10)


def build_safe_alert_payload(alert: SecurityAlert) -> Dict[str, Any]:
    """
    Builds data-hygienic webhook payload respecting Invariants I1 & I4.
    Document titles, contents, and encryption keys are strictly omitted.
    """
    now_iso = alert.timestamp.replace(tzinfo=timezone.utc).isoformat() if alert.timestamp else datetime.now(timezone.utc).isoformat()
    raw_meta = dict(alert.investigation_metadata or {})
    safe_meta = redact_sensitive_value("", raw_meta)

    # Invariant I1 & I4: Strip any accidentally embedded document titles or file data
    for forbidden in ["title", "document_title", "filename", "file_name", "content", "key", "password"]:
        if forbidden in safe_meta:
            safe_meta[forbidden] = "[REDACTED]"

    return {
        "event": "security_alert",
        "id": alert.id,
        "event_type": alert.event_type,
        "severity": alert.severity,
        "status": alert.status,
        "timestamp": now_iso,
        "summary": alert.summary,
        "actor_id": alert.actor_id,
        "target_user_id": alert.target_user_id,
        "target_document_id": alert.target_document_id,
        "session_id": alert.session_id,
        "request_id": alert.request_id,
        "investigation_metadata": safe_meta
    }


def dispatch_security_webhook(
    alert: SecurityAlert,
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
    max_retries: int = 3,
    client: Optional[httpx.Client] = None
) -> Tuple[bool, str]:
    """
    Dispatches outbound security webhook with HMAC-SHA256 signature and replay prevention.
    Returns: (success: bool, message: str)
    """
    url = webhook_url or settings.SECURITY_WEBHOOK_URL
    secret = webhook_secret or settings.SECURITY_WEBHOOK_SECRET

    if not url:
        return False, "Webhook dispatch skipped: No destination URL configured."

    # Enforce sliding-window rate limit per destination endpoint
    if not webhook_limiter.is_allowed(url):
        logger.warning("Security webhook suppressed due to rate limiting (alert %s, url %s)", alert.id, url)
        return False, "Webhook rate limit exceeded. Delivery suppressed."

    payload_dict = build_safe_alert_payload(alert)
    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    now_epoch = str(int(time.time()))
    delivery_id = str(uuid.uuid4())

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "TrustVault-Security-Webhook/1.0",
        "X-TrustVault-Delivery": delivery_id,
        "X-TrustVault-Event": alert.event_type,
        "X-TrustVault-Timestamp": now_epoch,
    }

    if secret:
        # Sign payload + timestamp to prevent replay attacks
        sign_data = now_epoch.encode("utf-8") + b"." + payload_bytes
        sig = compute_webhook_signature(sign_data, secret)
        headers["X-TrustVault-Signature"] = f"sha256={sig}"

    # Use supplied test client or transient client
    http_client = client or httpx.Client(timeout=5.0)
    should_close = client is None

    last_error = ""
    try:
        for attempt in range(1, max_retries + 1):
            try:
                resp = http_client.post(url, content=payload_bytes, headers=headers)
                if resp.status_code in (200, 201, 202, 204):
                    logger.info("Security webhook delivered successfully for alert %s (HTTP %s)", alert.id, resp.status_code)
                    return True, f"Delivered (HTTP {resp.status_code})"
                last_error = f"HTTP {resp.status_code}: {resp.text[:100]}"
            except Exception as e:
                last_error = str(e)

            if attempt < max_retries:
                time.sleep(0.1 * (2 ** (attempt - 1)))  # Exponential backoff: 0.1s, 0.2s
    finally:
        if should_close:
            http_client.close()

    logger.error("Failed to deliver security webhook for alert %s after %s attempts: %s", alert.id, max_retries, last_error)
    return False, f"Delivery failed: {last_error}"
