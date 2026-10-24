# Cloudflare Cache Rules & CDN Edge Security Configuration

## Overview
TrustVault enforces Invariant **I2 (Instant Revocation)**: permissions, access grants, session revocations, and emergency break-glass sessions must take effect immediately. To prevent content caching, stale authorization data, or leakage of confidential envelope ciphertext, Cloudflare CDN edges must strictly bypass all caching for API and content routes.

---

## 1. Cloudflare Cache Rule Definition

### Rule 1: Bypass API & Content Cache (Highest Priority)
- **Rule Name**: `TrustVault-Bypass-API-And-Content-Cache`
- **Scope / Expression**:
  ```text
  (http.host eq "trustvault.app" and starts_with(http.request.uri.path, "/api/"))
  ```
- **Actions**:
  - **Cache eligibility**: `Bypass cache`
  - **Origin cache control**: `Respect origin`
  - **Edge Cache TTL**: `Bypass`
  - **Browser Cache TTL**: `Respect origin`

### Rule 2: Static Asset Caching
- **Rule Name**: `TrustVault-Cache-Static-SPA-Assets`
- **Scope / Expression**:
  ```text
  (http.host eq "trustvault.app" and (starts_with(http.request.uri.path, "/assets/") or http.request.uri.path in {"/favicon.ico", "/robots.txt"}))
  ```
- **Actions**:
  - **Cache eligibility**: `Eligible for cache`
  - **Edge Cache TTL**: 7 days
  - **Browser Cache TTL**: 1 day

---

## 2. Origin Server Response Headers

TrustVault's backend automatically attaches the following defense-in-depth headers on all `/api/*` and `/download` responses:

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `Cache-Control` | `no-store, private` | Forbids caching in intermediate proxies, CDNs, and browser caches. |
| `Pragma` | `no-cache` | Legacy HTTP/1.0 cache prevention. |
| `Content-Disposition` | `attachment; filename="..."` | Ensures content is downloaded rather than executed inline. |
| `X-Content-Type-Options` | `nosniff` | Blocks MIME-type sniffing attacks. |
| `Cross-Origin-Resource-Policy` | `same-origin` | Forbids cross-origin inclusion or reads. |

---

## 3. Verification & Auditing

To verify that caching is properly bypassed on Cloudflare:
```bash
curl -I https://trustvault.app/api/v1/documents
```
Expected response headers:
```http
cf-cache-status: BYPASS
cache-control: no-store, private
pragma: no-cache
x-content-type-options: nosniff
cross-origin-resource-policy: same-origin
```
No `HIT` or `STALE` status may ever appear for `/api/*` endpoints.
