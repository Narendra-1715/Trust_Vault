"""
Enterprise Structured JSON Logging & Observability Engine (Phase 11).
Enforces:
1. Standardized JSON log formatting with ISO 8601 timestamps.
2. Distributed tracing correlation: request_id, correlation_id / trace_id, actor_id, client_ip via contextvars.
3. Automated sensitive data redaction filter (protects credentials, bearer tokens, decrypt keys, and plaintext).
"""

import sys
import json
import logging
import re
from datetime import datetime, timezone
from contextvars import ContextVar
from typing import Any, Dict, Optional

# Tracing context variables for asynchronous request tracking
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id", default="")
actor_id_ctx: ContextVar[str] = ContextVar("actor_id", default="anonymous")
client_ip_ctx: ContextVar[str] = ContextVar("client_ip", default="unknown")

# Redaction patterns for defense against credential and key leaks in logs
SENSITIVE_KEY_NAMES = {
    "password", "token", "access_token", "refresh_token", "secret", "authorization",
    "cookie", "key", "dek", "kek", "plaintext", "content", "api_key", "raw_token",
    "session_secret", "encryption_key"
}

BEARER_TOKEN_REGEX = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE)
JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+")
KEY_HEX_REGEX = re.compile(r"\b[0-9a-fA-F]{64}\b")


def redact_sensitive_value(key: str, value: Any) -> Any:
    """Recursively redacts sensitive keys and patterns in log values."""
    if value is None:
        return None

    if isinstance(key, str) and any(s in key.lower() for s in SENSITIVE_KEY_NAMES):
        return "[REDACTED]"

    if isinstance(value, str):
        # Redact bearer tokens and JWT patterns
        val = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED]", value)
        val = JWT_REGEX.sub("[REDACTED_JWT]", val)
        return val

    if isinstance(value, dict):
        return {k: redact_sensitive_value(str(k), v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [redact_sensitive_value("", item) for item in value]

    return value


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs sensitive strings from log messages and attributes."""
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED]", record.msg)
            record.msg = JWT_REGEX.sub("[REDACTED_JWT]", record.msg)
        elif isinstance(record.msg, dict):
            record.msg = redact_sensitive_value("", record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_sensitive_value("", record.args)
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(redact_sensitive_value("", a) for a in record.args)

        return True


class StructuredJSONFormatter(logging.Formatter):
    """
    Serializes LogRecords into standardized, SIEM-ingestible JSON entries.
    """
    def format(self, record: logging.LogRecord) -> str:
        # Standard baseline timestamp in ISO 8601 UTC
        now_utc = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()

        log_entry: Dict[str, Any] = {
            "timestamp": now_utc,
            "level": record.levelname,
            "service": "trustvault-backend",
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_ctx.get() or getattr(record, "request_id", ""),
            "correlation_id": correlation_id_ctx.get() or getattr(record, "correlation_id", ""),
            "actor_id": actor_id_ctx.get() or getattr(record, "actor_id", "anonymous"),
            "client_ip": client_ip_ctx.get() or getattr(record, "client_ip", "unknown")
        }

        # Include exception information if available
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Include caller file and line info for error diagnostics
        if record.levelno >= logging.ERROR:
            log_entry["caller"] = {
                "file": record.pathname,
                "line": record.lineno,
                "func": record.funcName
            }

        # Include extra custom attributes attached to LogRecord
        reserved = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
            "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "created", "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process", "message", "request_id", "correlation_id",
            "actor_id", "client_ip"
        }
        extras = {
            k: redact_sensitive_value(k, v)
            for k, v in record.__dict__.items()
            if k not in reserved and not k.startswith("_")
        }
        if extras:
            log_entry["extra"] = extras

        return json.dumps(log_entry, default=str)


def setup_structured_logging(log_level: str = "INFO"):
    """Configures root and application loggers to emit structured JSON with redaction."""
    root_logger = logging.getLogger()
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers
    has_json_handler = any(isinstance(h.formatter, StructuredJSONFormatter) for h in root_logger.handlers)
    if not has_json_handler:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredJSONFormatter())
        handler.addFilter(SensitiveDataFilter())
        root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Returns a logger pre-configured with sensitive data filtering."""
    logger = logging.getLogger(name)
    logger.addFilter(SensitiveDataFilter())
    return logger
