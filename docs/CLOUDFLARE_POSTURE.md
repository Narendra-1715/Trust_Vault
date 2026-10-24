# Cloudflare & Reverse Proxy Security Posture

This document details the enterprise-grade edge architecture, WAF configurations, caching rules, and direct-to-origin lockdown controls deployed on Cloudflare in front of TrustVault.

---

## 1. Edge Invariants & Perimeter Architecture

TrustVault assumes zero-trust principles behind Cloudflare. All client requests MUST transit Cloudflare's edge network. Direct connections to the origin web application (e.g. on Render) are strictly forbidden and cryptographically blocked.

```
+------------------+         +-------------------------------+         +---------------------+
|  Client Browser  |  HTTPS  |  Cloudflare Edge (WAF, DDoS)   |  HTTPS  |  Origin (Render)    |
|                  | =======>|  • SSL Full (Strict)          | =======>|  • Origin CA Cert   |
|                  |         |  • Managed Challenges (Threat)|         |  • Direct-IP Reject |
|                  |         |  • Cache Bypass on /api/*     |         |  • CF-Connecting-IP |
+------------------+         +-------------------------------+         +---------------------+
```

---

## 2. SSL/TLS Encryption Posture

- **Encryption Mode:** **Full (Strict)**
  - Cloudflare validates the origin server's TLS certificate signed by an authentic Certificate Authority or Cloudflare Origin CA.
  - Mitigates man-in-the-middle (MITM) attacks between Cloudflare and the origin.
- **Minimum TLS Version:** **TLS 1.3** (fallback TLS 1.2 minimum with AEAD cipher suites only: `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`).
- **HSTS (HTTP Strict Transport Security):**
  - Header: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
  - Automated HTTPS rewrites enabled.
  - Browser preload eligibility active.

---

## 3. Web Application Firewall (WAF) & Rate Limiting

### 3.1 Managed Rulesets
- **Cloudflare Managed Ruleset:** Enabled (Log & Block). Protects against OWASP Top 10 vulnerabilities (SQL injection, XSS, Remote Code Execution, Path Traversal).
- **OWASP Core Ruleset:** Enabled with Paranoia Level 2 and Anomaly Score threshold 25.

### 3.2 Custom Threat Mitigation Rules
1. **Suspicious ASN & High-Threat Challenging:**
   - Expression: `(cf.threat_score ge 15) or (ip.geoip.asnum in {<known_bulletproof_hosters>})`
   - Action: **Managed Challenge** (Interactive Turnstile without breaking legitimate users).
2. **Tor Exit Node & Anonymous Proxy Hardening:**
   - Expression: `(ip.geoip.is_tor) or (ip.threat_score ge 40)`
   - Action: **Block** or **Interactive Challenge** on authentication endpoints (`/api/v1/auth/*`).
3. **Account-Lockout & Brute-Force Rate Limiting Rule:**
   - Path: `/api/v1/auth/login`
   - Characteristics: `IP + Username`
   - Threshold: **5 requests per minute**
   - Action: **Block with 429 response** and `Retry-After`.

---

## 4. Cache Bypass Architecture (`/api/*`)

To enforce Invariant I2 (instant permission revocation) and Invariant I3 (zero existence leaks), **all dynamic content, API queries, downloads, and preview images must bypass Cloudflare cache**:

- **Cache Rule 1: Bypass API & Content Cache**
  - Match: `(http.request.uri.path starts_with "/api/")`
  - Cache Eligibility: **Bypass Cache**
  - Edge TTL: No cache
  - Browser TTL: Respect origin headers (`Cache-Control: no-store, private`, `Pragma: no-cache`)
- **Cache Rule 2: Static Assets Only**
  - Match: `(http.request.uri.path starts_with "/assets/") or (http.request.uri.path in {"/favicon.svg", "/robots.txt"})`
  - Cache Eligibility: **Eligible for cache** (30 days immutable, utilizing Vite asset hashing).

---

## 5. Direct-to-Origin Lockdown (Origin Isolation)

To prevent attackers from discovering origin IP addresses and bypassing Cloudflare WAF:

### 5.1 Cloudflare IP Whitelisting
Configure origin host firewall / network ingress rules to accept incoming traffic **exclusively** from Cloudflare's published CIDR ranges:

**IPv4 Ranges:**
```
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
```

**IPv6 Ranges:**
```
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
```

### 5.2 Application-Layer Direct-to-Origin Validation
When `ENFORCE_CLOUDFLARE_ORIGIN=True` in production settings:
1. `SecurityHeadersMiddleware` verifies the presence and integrity of:
   - `CF-Ray`: Unique Cloudflare edge trace token.
   - `CF-Connecting-IP`: Edge-verified client IP.
2. Any request missing these headers or originating from outside the Cloudflare mesh is immediately terminated with `403 Forbidden: Direct-to-origin access is forbidden`.

---

## 6. Verification Checklist

| Requirement | Setting | Verification Status |
| :--- | :--- | :--- |
| **SSL/TLS Mode** | Full (Strict) | Enforced |
| **HSTS** | `max-age=63072000; includeSubDomains; preload` | Validated in automated tests |
| **API Cache Bypass** | `Cache-Control: no-store, private` | Enforced on `/api/*` |
| **Edge WAF** | OWASP CRS + Anomaly Scoring | Active |
| **Rate Limiting** | 5/min on Auth, 10/min on Downloads | Enforced in `rate_limit.py` |
| **Origin Isolation** | Cloudflare IP validation + `CF-Connecting-IP` | Verified in middleware |
