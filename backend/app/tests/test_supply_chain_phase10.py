"""Phase 10 Test Suite: Supply Chain Security, Pinned Dependencies, and CycloneDX SBOMs.
Validates:
1. Strict dependency pinning (exact == in Python, exact semantic versions in package.json).
2. Deterministic lockfile presence and SHA integrity hashes.
3. CycloneDX 1.6 Software Bill of Materials (SBOM) structure, metadata, and component completeness.
4. Supply chain auditor gate execution and violation detection.
"""

import sys
import os
import json
import subprocess
import importlib.util
from pathlib import Path
import pytest

# Dynamically load audit_supply_chain from repository root scripts directory
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_AUDIT_SCRIPT = _REPO_ROOT / "scripts" / "audit_supply_chain.py"

if not _AUDIT_SCRIPT.exists():
    raise FileNotFoundError(f"Supply chain auditor script not found at {_AUDIT_SCRIPT}")

_spec = importlib.util.spec_from_file_location("scripts.audit_supply_chain", str(_AUDIT_SCRIPT))
_audit_mod = importlib.util.module_from_spec(_spec)
sys.modules["scripts.audit_supply_chain"] = _audit_mod
_spec.loader.exec_module(_audit_mod)

check_backend_pinning = _audit_mod.check_backend_pinning
check_frontend_pinning = _audit_mod.check_frontend_pinning
check_sbom_validity = _audit_mod.check_sbom_validity
ROOT_DIR = _audit_mod.ROOT_DIR


def test_backend_requirements_pinning_and_no_loose_ranges():
    """
    Phase 10 Requirement:
    All backend Python direct dependencies must be pinned to exact versions.
    Floating ranges (>=, <=, >, <, ~=, *) are prohibited.
    """
    req_file = ROOT_DIR / "backend" / "requirements.txt"
    assert req_file.exists(), "backend/requirements.txt must exist"

    errors = check_backend_pinning(req_file)
    assert len(errors) == 0, f"Found unpinned backend dependencies: {errors}"

    with open(req_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    # Check key dependencies are pinned
    required_pkgs = ["fastapi", "cryptography", "sqlalchemy", "pydantic", "PyJWT"]
    pinned_names = [line.split("==")[0].split("[")[0].strip() for line in lines]
    for pkg in required_pkgs:
        assert pkg in pinned_names, f"Expected {pkg} to be pinned in requirements.txt"


def test_frontend_package_json_pinning_and_no_loose_ranges():
    """
    Phase 10 Requirement:
    All frontend npm packages must be pinned to exact versions without carets or tildes.
    """
    pkg_file = ROOT_DIR / "frontend" / "package.json"
    assert pkg_file.exists(), "frontend/package.json must exist"

    errors = check_frontend_pinning(pkg_file)
    assert len(errors) == 0, f"Found unpinned frontend dependencies: {errors}"

    with open(pkg_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    deps = data.get("dependencies", {})
    dev_deps = data.get("devDependencies", {})

    assert "react" in deps
    assert "vite" in dev_deps
    # Verify no caret (^) or tilde (~) in version strings
    for name, version in {**deps, **dev_deps}.items():
        assert not version.startswith("^"), f"{name} starts with ^: {version}"
        assert not version.startswith("~"), f"{name} starts with ~: {version}"


def test_deterministic_lockfiles_exist_and_valid():
    """
    Phase 10 Requirement:
    Deterministic lockfiles must exist for both backend (requirements.lock)
    and frontend (package-lock.json with SHA-512 integrity hashes).
    """
    backend_lock = ROOT_DIR / "backend" / "requirements.lock"
    frontend_lock = ROOT_DIR / "frontend" / "package-lock.json"

    assert backend_lock.exists(), "backend/requirements.lock must exist"
    assert frontend_lock.exists(), "frontend/package-lock.json must exist"

    # Backend lockfile must be non-empty and contain pinned versions
    backend_content = backend_lock.read_text(encoding="utf-8")
    assert "fastapi==" in backend_content
    assert "cryptography==" in backend_content
    assert "pip-compile" in backend_content

    # Frontend lockfile must have lockfileVersion 3 and integrity hashes
    with open(frontend_lock, "r", encoding="utf-8") as f:
        f_lock_data = json.load(f)

    assert f_lock_data.get("lockfileVersion") == 3
    packages = f_lock_data.get("packages", {})
    # Check that packages have cryptographic SHA-512 integrity hashes
    has_integrity = False
    for pkg_path, meta in packages.items():
        if "integrity" in meta and meta["integrity"].startswith("sha512-"):
            has_integrity = True
            break
    assert has_integrity, "package-lock.json packages must contain sha512 integrity hashes"


def test_cyclonedx_sboms_structure_and_completeness():
    """
    Phase 10 Requirement:
    CycloneDX 1.6 SBOMs must exist, parse as valid JSON, have bomFormat == 'CycloneDX',
    and contain components with names, versions, and package URLs (purls).
    """
    backend_sbom = ROOT_DIR / "sbom" / "backend-sbom.cdx.json"
    frontend_sbom = ROOT_DIR / "sbom" / "frontend-sbom.cdx.json"

    assert backend_sbom.exists(), "sbom/backend-sbom.cdx.json must exist"
    assert frontend_sbom.exists(), "sbom/frontend-sbom.cdx.json must exist"

    # Validate Backend SBOM
    b_errors = check_sbom_validity(backend_sbom, "backend")
    assert len(b_errors) == 0, f"Backend SBOM validation errors: {b_errors}"

    with open(backend_sbom, "r", encoding="utf-8") as f:
        b_data = json.load(f)
    assert b_data["bomFormat"] == "CycloneDX"
    b_comp_names = [c["name"] for c in b_data.get("components", [])]
    assert "fastapi" in b_comp_names
    assert "cryptography" in b_comp_names

    # Validate Frontend SBOM
    f_errors = check_sbom_validity(frontend_sbom, "frontend")
    assert len(f_errors) == 0, f"Frontend SBOM validation errors: {f_errors}"

    with open(frontend_sbom, "r", encoding="utf-8") as f:
        f_data = json.load(f)
    assert f_data["bomFormat"] == "CycloneDX"
    f_comp_names = [c["name"] for c in f_data.get("components", [])]
    assert "react" in f_comp_names or any("react" in name for name in f_comp_names)


def test_audit_supply_chain_script_execution():
    """
    Phase 10 Requirement:
    The supply chain verification gate script runs successfully and exits with code 0.
    """
    script_path = ROOT_DIR / "scripts" / "audit_supply_chain.py"
    assert script_path.exists(), "scripts/audit_supply_chain.py must exist"

    cmd = [sys.executable, str(script_path), "--skip-network"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT_DIR))
    assert proc.returncode == 0, f"Supply chain auditor failed with {proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
    assert "[SUCCESS] All Supply Chain & SBOM gates passed cleanly." in proc.stdout


def test_audit_gate_detects_unpinned_violations_and_invalid_sbom(tmp_path):
    """
    Phase 10 Requirement:
    The gate logic actively rejects unpinned dependencies and malformed SBOMs.
    """
    # 1. Test unpinned Python manifest
    bad_req = tmp_path / "bad_requirements.txt"
    bad_req.write_text("fastapi>=0.100.0\nuvicorn\nrequests~=2.30.0\n", encoding="utf-8")
    b_errs = check_backend_pinning(bad_req)
    assert len(b_errs) == 3
    assert any("fastapi" in e for e in b_errs)
    assert any("uvicorn" in e for e in b_errs)

    # 2. Test unpinned Node.js manifest
    bad_pkg = tmp_path / "bad_package.json"
    bad_pkg.write_text(json.dumps({
        "dependencies": {
            "react": "^19.0.0",
            "lodash": "latest"
        },
        "devDependencies": {
            "vite": "~5.0.0"
        }
    }), encoding="utf-8")
    f_errs = check_frontend_pinning(bad_pkg)
    assert len(f_errs) == 3
    assert any("react" in e for e in f_errs)
    assert any("lodash" in e for e in f_errs)
    assert any("vite" in e for e in f_errs)

    # 3. Test invalid SBOM
    bad_sbom = tmp_path / "bad_sbom.json"
    bad_sbom.write_text(json.dumps({"bomFormat": "UnknownFormat", "components": []}), encoding="utf-8")
    s_errs = check_sbom_validity(bad_sbom, "test")
    assert len(s_errs) >= 2
    assert any("UnknownFormat" in e for e in s_errs)
    assert any("Zero components" in e for e in s_errs)
