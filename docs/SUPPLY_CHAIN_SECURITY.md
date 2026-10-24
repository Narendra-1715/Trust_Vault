# TrustVault Supply Chain Security and Dependency Posture (Phase 10)

This document outlines TrustVault's enterprise supply chain security architecture, dependency governance, vulnerability gate policies, and Software Bill of Materials (SBOM) lifecycle management.

---

## 1. Zero-Trust Dependency Pinning Policy

To guarantee deterministic, byte-for-byte reproducible builds across local environments, CI/CD runners, and production deployments, TrustVault enforces strict dependency pinning.

### 1.1 Backend Python (`backend/requirements.txt` & `backend/requirements.lock`)
- **Direct Manifest (`requirements.txt`)**: All primary dependencies must be pinned using exact equality operators (`==`). Floating versions, wildcards (`*`), minimum versions (`>=`), and compatible release ranges (`~=`) are **strictly prohibited** and blocked by CI.
- **Transitive Lockfile (`requirements.lock`)**: Generated via `pip-tools` (`pip-compile`). Freezes the exact transitive dependency closure with full dependency tree provenance annotations.

### 1.2 Frontend Node.js (`frontend/package.json` & `frontend/package-lock.json`)
- **Direct Manifest (`package.json`)**: All `dependencies` and `devDependencies` must specify exact semantic versions (e.g. `"react": "19.3.1"`). Carets (`^`) and tildes (`~`) are disallowed to eliminate silent minor/patch drift during deployment.
- **Integrity Lockfile (`package-lock.json`)**: Version 3 lockfile format with cryptographic SHA-512 subresource integrity hashes (`integrity: sha512-...`) for every installed package. Production builds use `npm ci` to verify hashes before extraction.

---

## 2. Automated Vulnerability Gates

TrustVault incorporates automated vulnerability scanning directly into the build and test pipelines. Any build containing unpatched vulnerabilities is automatically failed and rejected at the gate.

### 2.1 Backend Python Scanning (`pip-audit`)
- **Tooling**: `pip-audit` (utilizing the Python Packaging Advisory Database and Open Source Vulnerabilities / OSV API).
- **Execution**:
  ```bash
  python -m pip_audit -r backend/requirements.txt
  ```
- **Policy**: Fails the pipeline if any known vulnerability with an available patch exists.

### 2.2 Frontend Node.js Scanning (`npm audit`)
- **Tooling**: `npm audit` (querying the GitHub Advisory Database).
- **Execution**:
  ```bash
  npm --prefix frontend audit --json
  ```
- **Policy**: Blocks builds on any `CRITICAL` or `HIGH` severity CVEs.

### 2.3 Vulnerability Remediation SLAs

| Severity | Common Vulnerability Scoring System (CVSS) | Target Remediation SLA |
| :--- | :--- | :--- |
| **Critical** | 9.0 – 10.0 | **Within 24 hours** (immediate hotfix release) |
| **High** | 7.0 – 8.9 | **Within 7 calendar days** |
| **Medium** | 4.0 – 6.9 | **Within 30 calendar days** |
| **Low** | 0.1 – 3.9 | **Within 90 calendar days / next minor release** |

---

## 3. Software Bill of Materials (SBOM) Architecture

TrustVault continuously maintains machine-readable Software Bill of Materials following the **CycloneDX 1.6** industry standard.

### 3.1 Artifacts
- **Backend SBOM**: [`sbom/backend-sbom.cdx.json`](file:///c:/Users/chint/OneDrive/Desktop/Trust_val/sbom/backend-sbom.cdx.json)
  - Generated via `cyclonedx-bom` from `backend/requirements.lock`.
  - Captures Python ecosystem components, exact versions, licenses, and Package URLs (`pkg:pypi/...`).
- **Frontend SBOM**: [`sbom/frontend-sbom.cdx.json`](file:///c:/Users/chint/OneDrive/Desktop/Trust_val/sbom/frontend-sbom.cdx.json)
  - Generated via `@cyclonedx/cyclonedx-npm` from `frontend/package-lock.json`.
  - Captures npm runtime and build-time packages, licenses, component trees, and Package URLs (`pkg:npm/...`).

### 3.2 Automated SBOM Generation Commands
```bash
# Backend SBOM
python -m cyclonedx_py requirements backend/requirements.lock --of JSON -o sbom/backend-sbom.cdx.json

# Frontend SBOM
cd frontend && npx --yes @cyclonedx/cyclonedx-npm --output-file ../sbom/frontend-sbom.cdx.json
```

---

## 4. Anti-Tampering & Supply Chain Attacks Defense

TrustVault implements defense-in-depth against emerging supply chain threat vectors:

### 4.1 Dependency Confusion & Typosquatting
- External packages are sourced exclusively from official authoritative indexes (`pypi.org`, `registry.npmjs.org`).
- Custom internal namespaces (if any) are configured with explicit index-url scoping to prevent malicious public package shadowing.
- Strict package name allowlisting and lockfile checks prevent typosquatting attacks (e.g. `reqeusts` vs `requests`).

### 4.2 Build-Time Code Execution Prevention
- Lockfile hashes guarantee that package tarballs have not been tampered with or modified upstream.
- Pre-install / post-install scripts in npm packages are audited during dependency addition.
- Python binary wheels are preferred over arbitrary compilation scripts where pre-built binaries are cryptographically signed.

### 4.3 Secret Leakage & Manifest Hygiene
- No sensitive keys, tokens, or environment credentials may ever appear in lockfiles, manifests, or SBOM artifacts.
- Automated tests inspect manifest metadata to ensure zero leaked secrets.

---

## 5. Enterprise Verification CLI (`scripts/audit_supply_chain.py`)

A unified audit script provides single-command verification for CI/CD runners, local developers, and automated audits:

```bash
# Run full supply chain validation (pinning, lockfiles, SBOMs, live vulnerability scans)
python scripts/audit_supply_chain.py

# Offline verification (pinning, lockfiles, SBOM structural checks)
python scripts/audit_supply_chain.py --skip-network
```
Exits with `0` on clean state and `1` on any supply chain violation.
