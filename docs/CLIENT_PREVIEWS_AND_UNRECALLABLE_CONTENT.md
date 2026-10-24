# Client Previews & Unrecallable Content Security Model

## Overview
TrustVault provides confidential document protection through envelope encryption, centralized Policy Decision Point (PDP) enforcement, and real-time mid-stream revocation. However, enterprise security engineering demands honest disclosure of physical and cryptographic trust boundaries.

---

## 1. Document Previews (Server-Generated Page Images)

To minimize the distribution of raw document files to client endpoints:
1. **Server-Side Rendering**: In-browser document previews are rendered via isolated server-side workers as converted raster images (e.g. WebP/PNG page slices) or sandboxed SVG representations, rather than transmitting full raw binaries (`.pdf`, `.docx`, `.xlsx`) to client memory.
2. **Preview Permissions (`VIEW` vs `DOWNLOAD`)**:
   - The Central Authorization Service strictly separates `Action.VIEW` (previewing metadata and page images) from `Action.DOWNLOAD` (streaming the complete raw binary).
   - Principals granted `READ` permission are restricted to `VIEW` only when the security policy or document classification enforces preview-only restrictions.

---

## 2. Invariant: Unrecallable Content Disclaimer

> [!IMPORTANT]
> **Physical Boundary Invariant**: Once document content has been downloaded, printed, photographed, or screenshotted to a client endpoint or physical device, **it cannot be cryptographically or remotely recalled, wiped, or undone by TrustVault**.

### Explicit Out-of-Scope Threat Vectors:
1. **Downloaded Content Persistence**: If a user had an active grant and completed a download before revocation, their local copy of that file on disk is outside the system's trust boundary.
2. **Visual & Screen Capture**: Screen capture utilities, external mobile cameras, and browser print-to-PDF cannot be prevented by web software once pixels are rendered on a monitor.
3. **Compromised Endpoints**: Keyloggers, compromised browser extensions, or OS rootkits on an authorized user's workstation.

### Controls Enforced by TrustVault:
- **Instant Revocation (Invariant I2)**: The exact moment an owner revokes access or a TTL grant expires, any future requests and any in-flight streaming downloads are severed within milliseconds.
- **Crypto-Shredding (Invariant I1 & I4)**: Deleting the wrapped DEK ensures all centralized server copies and historical backups become permanently mathematically unrecoverable.
- **Tamper-Evident Ledger (Invariant I5)**: Every access grant, download, and mid-stream revocation is recorded in the cryptographically chained audit log.
