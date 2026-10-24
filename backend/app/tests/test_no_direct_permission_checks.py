"""Linting test that verifies NO route handlers perform ad-hoc permission checks
or bypass the central AuthorizationService (PDP).
Enforces Architectural Decision: All access decisions MUST route through AuthorizationService.
"""

import os
import re
import pytest

API_V1_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "api", "v1"))

# Allowed files that legitimately query DocumentPermission for data retrieval (not access decisions)
# e.g., permissions.py for listing grants or updating them
PERMITTED_PERMISSION_QUERIES = {
    "permissions.py",      # API endpoint for managing permissions
    "access_requests.py", # Converting access requests to grants
    "access_reviews.py",  # Listing grants for periodic review
    "ai.py",              # Creating approved grants from AI suggestions
    "admin.py",           # Break-glass & admin inspection
}

FORBIDDEN_PATTERNS = [
    # Direct authorization checks without AuthorizationService
    r"db\.query\(DocumentPermission\)\.filter\(.*permission_level\s*==",
    r"user\.role\s*==\s*[\"']admin[\"']\s*(?:and|or|\:)\s*(?:pass|return True)",
]

def test_no_direct_permission_checks_in_routes():
    violations = []
    
    for filename in os.listdir(API_V1_DIR):
        if not filename.endswith(".py"):
            continue
            
        filepath = os.path.join(API_V1_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        for pattern in FORBIDDEN_PATTERNS:
            matches = re.finditer(pattern, content)
            for m in matches:
                violations.append(f"{filename}: matched forbidden pattern '{pattern}' at char {m.start()}")

    assert not violations, f"Architectural Invariant Violated: Found direct permission checks bypassing AuthorizationService:\n" + "\n".join(violations)

def test_routes_use_authorization_service():
    """Verify core document manipulation routes import and invoke AuthorizationService."""
    doc_route_file = os.path.join(API_V1_DIR, "documents.py")
    with open(doc_route_file, "r", encoding="utf-8") as f:
        content = f.read()

    assert "from app.services.authorization import AuthorizationService, Action" in content
    assert "AuthorizationService.enforce" in content
    assert "Action.DOWNLOAD" in content
    assert "Action.EDIT" in content
    assert "Action.DELETE" in content
    assert "Action.ROLLBACK" in content
    assert "Action.RESTORE" in content
