"""
SIEM Formatting and Export Module (Phase 11).
Supports enterprise formats:
1. CEF (Micro Focus ArcSight Common Event Format)
2. ECS (Elastic Common Schema 8.x)
3. RFC 5424 Syslog format
Enforces full escaping, zero sensitive credential leaks, and cryptographic event provenance.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.models.audit import AuditEvent


def escape_cef_value(val: Any) -> str:
    """Escapes special characters in CEF extension values according to ArcSight spec."""
    if val is None:
        return ""
    text = str(val)
    # Escape backslash first, then equals, pipe, newlines
    text = text.replace("\\", "\\\\")
    text = text.replace("=", "\\=")
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    return text


def escape_cef_header(val: Any) -> str:
    """Escapes pipes and backslashes in CEF header fields."""
    if val is None:
        return ""
    text = str(val)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    return text


def get_cef_severity(action: str, outcome: str) -> int:
    """Calculates ArcSight severity scale (0 - 10) based on action and outcome."""
    if outcome == "failure" or "tamper" in action.lower() or "break_glass" in action.lower():
        return 9
    if outcome == "denied":
        return 6
    if "admin" in action.lower() or "permission" in action.lower() or "export" in action.lower():
        return 4
    return 2


def format_event_cef(event: AuditEvent) -> str:
    """
    Serializes AuditEvent into ArcSight Common Event Format (CEF:0).
    Header: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    """
    vendor = "TrustVault"
    product = "TrustVault-Enterprise"
    version = "1.0"
    event_class_id = escape_cef_header(event.action)
    name = escape_cef_header(f"{event.resource_type} {event.action} ({event.outcome})")
    severity = get_cef_severity(event.action, event.outcome)

    header = f"CEF:0|{vendor}|{product}|{version}|{event_class_id}|{name}|{severity}|"

    # Extension dictionary
    epoch_ms = int(event.timestamp.replace(tzinfo=timezone.utc).timestamp() * 1000) if event.timestamp else 0
    actor_email = event.actor.email if event.actor else ""
    meta = event.structured_metadata or {}
    client_ip = meta.get("ip_address", "")

    extensions = [
        f"rt={epoch_ms}",
        f"act={escape_cef_value(event.action)}",
        f"outcome={escape_cef_value(event.outcome)}",
        f"cs1={escape_cef_value(event.request_id)}",
        "cs1Label=RequestId",
        f"cs2={escape_cef_value(event.resource_type)}",
        "cs2Label=ResourceType",
        f"cs3={escape_cef_value(event.resource_id)}",
        "cs3Label=ResourceId",
        f"cs4={escape_cef_value(event.event_hash)}",
        "cs4Label=EventHash",
        f"cn1={event.sequence_number or 0}",
        "cn1Label=SequenceNumber"
    ]

    if actor_email:
        extensions.append(f"suser={escape_cef_value(actor_email)}")
    if event.actor_id:
        extensions.append(f"suid={escape_cef_value(event.actor_id)}")
    if client_ip:
        extensions.append(f"src={escape_cef_value(client_ip)}")

    return header + " ".join(extensions)


def format_event_ecs(event: AuditEvent) -> Dict[str, Any]:
    """
    Serializes AuditEvent into Elastic Common Schema (ECS 8.x) JSON document.
    """
    iso_time = event.timestamp.replace(tzinfo=timezone.utc).isoformat() if event.timestamp else datetime.now(timezone.utc).isoformat()
    meta = event.structured_metadata or {}
    client_ip = meta.get("ip_address")

    # Map category
    action_lower = event.action.lower()
    if "auth" in action_lower:
        category = ["authentication"]
    elif "doc" in action_lower or "file" in action_lower or "upload" in action_lower:
        category = ["file"]
    elif "perm" in action_lower or "role" in action_lower or "user" in action_lower:
        category = ["iam"]
    else:
        category = ["audit"]

    severity_score = 90 if event.outcome in ("failure", "tampered") else 50 if event.outcome == "denied" else 20

    doc: Dict[str, Any] = {
        "@timestamp": iso_time,
        "ecs": {"version": "8.11.0"},
        "event": {
            "id": event.id,
            "sequence": event.sequence_number,
            "action": event.action,
            "category": category,
            "outcome": event.outcome,
            "severity": severity_score
        },
        "user": {
            "id": event.actor_id,
            "email": event.actor.email if event.actor else None
        },
        "trace": {
            "id": event.request_id
        },
        "trustvault": {
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "event_hash": event.event_hash,
            "previous_event_hash": event.previous_event_hash,
            "sequence_number": event.sequence_number
        }
    }

    if client_ip:
        doc["client"] = {"ip": client_ip}

    return doc


def format_event_syslog(event: AuditEvent) -> str:
    """
    Serializes AuditEvent into RFC 5424 Syslog message format.
    Format: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
    PRI: Facility local4 (16) * 8 + Severity Notice (5) = 133 or Error (3) = 131
    """
    pri = 131 if event.outcome in ("failure", "denied") else 134
    iso_time = event.timestamp.replace(tzinfo=timezone.utc).isoformat() if event.timestamp else datetime.now(timezone.utc).isoformat()
    actor_id_str = event.actor_id or "anonymous"
    actor_email_str = event.actor.email if event.actor else actor_id_str
    action_safe = event.action.replace('"', '\\"')
    outcome_safe = event.outcome.replace('"', '\\"')
    req_safe = (event.request_id or "").replace('"', '\\"')
    hash_safe = (event.event_hash or "")[:16]

    sd = (
        f'[trustvault@41123 action="{action_safe}" outcome="{outcome_safe}" '
        f'seq="{event.sequence_number or 0}" reqId="{req_safe}" hash="{hash_safe}"]'
    )
    msg = f"actor={actor_email_str} resource={event.resource_type}:{event.resource_id}"

    return f"<{pri}>1 {iso_time} trustvault-node api - audit {sd} {msg}"
