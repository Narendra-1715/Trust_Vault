#!/usr/bin/env python3
"""
Enterprise Supply Chain & Dependency Security Auditor (Phase 10).
Validates:
1. Strict dependency pinning (exact versions, zero loose ranges in requirements and package.json).
2. Lockfile integrity and presence (backend/requirements.lock, frontend/package-lock.json).
3. CycloneDX SBOM validity and structural compliance.
4. Vulnerability scanning gates (pip-audit and npm audit).
"""

import sys
import os
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Any

ROOT_DIR = Path(__file__).resolve().parent.parent

def check_backend_pinning(req_path: Path) -> List[str]:
    errors = []
    if not req_path.exists():
        return [f"Requirements file not found: {req_path}"]
    
    with open(req_path, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # Must contain exact pinning == and no loose specifiers
            if "==" not in line:
                errors.append(f"Line {line_no}: Unpinned package '{line}'. Must use exact '=='.")
            elif any(loose in line for loose in [">=", "<=", ">", "<", "~=", "*"]):
                errors.append(f"Line {line_no}: Loose range in '{line}'. Must be pinned exactly.")
    return errors


def check_frontend_pinning(pkg_path: Path) -> List[str]:
    errors = []
    if not pkg_path.exists():
        return [f"package.json not found: {pkg_path}"]
    
    with open(pkg_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    for section in ["dependencies", "devDependencies"]:
        deps: Dict[str, str] = data.get(section, {})
        for name, version in deps.items():
            if re.search(r"[\^~*><=]|latest", version):
                errors.append(
                    f"{section} '{name}': '{version}' contains loose range. Must be exact version (e.g. '1.2.3')."
                )
    return errors


def check_sbom_validity(sbom_path: Path, expected_name: str) -> List[str]:
    errors = []
    if not sbom_path.exists():
        return [f"SBOM file not found: {sbom_path}"]
    
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return [f"Invalid JSON in SBOM {sbom_path}: {e}"]

    if data.get("bomFormat") != "CycloneDX":
        errors.append(f"{sbom_path.name}: Expected bomFormat 'CycloneDX', got '{data.get('bomFormat')}'")

    if not data.get("specVersion"):
        errors.append(f"{sbom_path.name}: Missing CycloneDX 'specVersion'")

    components = data.get("components", [])
    if not isinstance(components, list) or len(components) == 0:
        errors.append(f"{sbom_path.name}: Zero components registered in SBOM.")
    else:
        # Check component schema integrity
        for idx, comp in enumerate(components[:5]):  # Sample check first few
            if not comp.get("name") or not comp.get("version"):
                errors.append(f"{sbom_path.name} component #{idx}: Missing name or version.")

    return errors


def run_pip_audit(req_path: Path) -> Tuple[bool, str]:
    cmd = [sys.executable, "-m", "pip_audit", "-r", str(req_path), "--format", "json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT_DIR), timeout=60)
        if proc.returncode == 0:
            return True, "No known vulnerabilities found in Python dependencies."
        return False, f"pip-audit detected vulnerabilities or failed (exit code {proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    except subprocess.TimeoutExpired:
        return False, "pip-audit scan timed out after 60s."
    except Exception as e:
        return False, f"Error running pip-audit: {e}"


def run_npm_audit(frontend_dir: Path) -> Tuple[bool, str]:
    cmd = ["npm", "--prefix", str(frontend_dir), "audit", "--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT_DIR), shell=True, timeout=60)
        try:
            audit_data = json.loads(proc.stdout)
            vuln_summary = audit_data.get("metadata", {}).get("vulnerabilities", {})
            high = vuln_summary.get("high", 0)
            critical = vuln_summary.get("critical", 0)
            total = vuln_summary.get("total", 0)
            if high > 0 or critical > 0:
                return False, f"npm audit detected {critical} critical and {high} high vulnerabilities (Total: {total})."
            return True, f"npm audit passed (Total vulnerabilities: {total}, 0 critical/high)."
        except json.JSONDecodeError:
            if proc.returncode == 0:
                return True, "npm audit passed."
            return False, f"npm audit failed:\n{proc.stdout}\n{proc.stderr}"
    except subprocess.TimeoutExpired:
        return False, "npm audit scan timed out after 60s."
    except Exception as e:
        return False, f"Error running npm audit: {e}"


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="TrustVault Supply Chain & SBOM Gate")
    parser.add_argument("--skip-network", action="store_true", help="Skip live vulnerability scans against external databases")
    args = parser.parse_args()

    print("======================================================")
    print("TrustVault Enterprise Supply Chain Security Audit")
    print("======================================================\n")

    all_passed = True

    # 1. Check Python requirements pinning
    req_file = ROOT_DIR / "backend" / "requirements.txt"
    print(f"[*] Auditing Python dependencies ({req_file})...")
    backend_pinning_errors = check_backend_pinning(req_file)
    if backend_pinning_errors:
        print("  [FAIL] Python pinning violations:")
        for err in backend_pinning_errors:
            print(f"    - {err}")
        all_passed = False
    else:
        print("  [PASS] All Python direct dependencies are strictly pinned.")

    # 2. Check Node.js package pinning
    pkg_file = ROOT_DIR / "frontend" / "package.json"
    print(f"[*] Auditing Node.js dependencies ({pkg_file})...")
    frontend_pinning_errors = check_frontend_pinning(pkg_file)
    if frontend_pinning_errors:
        print("  [FAIL] Node.js pinning violations:")
        for err in frontend_pinning_errors:
            print(f"    - {err}")
        all_passed = False
    else:
        print("  [PASS] All Node.js dependencies are strictly pinned.")

    # 3. Check Lockfile presence
    backend_lock = ROOT_DIR / "backend" / "requirements.lock"
    frontend_lock = ROOT_DIR / "frontend" / "package-lock.json"
    print("[*] Auditing deterministic lockfiles...")
    if not backend_lock.exists():
        print(f"  [FAIL] Missing backend lockfile: {backend_lock}")
        all_passed = False
    else:
        print(f"  [PASS] Backend lockfile present ({backend_lock.name}).")

    if not frontend_lock.exists():
        print(f"  [FAIL] Missing frontend lockfile: {frontend_lock}")
        all_passed = False
    else:
        print(f"  [PASS] Frontend lockfile present ({frontend_lock.name}).")

    # 4. Check SBOMs
    backend_sbom = ROOT_DIR / "sbom" / "backend-sbom.cdx.json"
    frontend_sbom = ROOT_DIR / "sbom" / "frontend-sbom.cdx.json"
    print("[*] Auditing CycloneDX Software Bill of Materials (SBOM)...")
    
    b_sbom_errs = check_sbom_validity(backend_sbom, "backend")
    if b_sbom_errs:
        print("  [FAIL] Backend SBOM errors:")
        for err in b_sbom_errs:
            print(f"    - {err}")
        all_passed = False
    else:
        print("  [PASS] Backend CycloneDX SBOM is valid.")

    f_sbom_errs = check_sbom_validity(frontend_sbom, "frontend")
    if f_sbom_errs:
        print("  [FAIL] Frontend SBOM errors:")
        for err in f_sbom_errs:
            print(f"    - {err}")
        all_passed = False
    else:
        print("  [PASS] Frontend CycloneDX SBOM is valid.")

    # 5. Live Vulnerability Scans
    if not args.skip_network:
        print("[*] Running pip-audit against PyPI Advisory Database...")
        pip_ok, pip_msg = run_pip_audit(req_file)
        if not pip_ok:
            print(f"  [FAIL] {pip_msg}")
            all_passed = False
        else:
            print(f"  [PASS] {pip_msg}")

        print("[*] Running npm audit against GitHub Advisory Database...")
        npm_ok, npm_msg = run_npm_audit(ROOT_DIR / "frontend")
        if not npm_ok:
            print(f"  [FAIL] {npm_msg}")
            all_passed = False
        else:
            print(f"  [PASS] {npm_msg}")
    else:
        print("[*] Skipping live vulnerability network scan (--skip-network enabled).")

    print("\n------------------------------------------------------")
    if all_passed:
        print("[SUCCESS] All Supply Chain & SBOM gates passed cleanly.")
        return 0
    else:
        print("[FAILURE] Supply chain security audit failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
