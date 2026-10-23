# TrustVault Self-Hosted Deployment Guide with Coolify

This guide details how to self-host TrustVault on your own Virtual Private Server (VPS) using [Coolify](https://coolify.io) ([GitHub](https://github.com/coollabsio/coolify)) — the open-source, self-hosted alternative to Render, Heroku, and Netlify.

---

## Why Coolify Solves the Persistent Storage Challenge

On platforms like Render's free tier, local disk storage is ephemeral and is wiped on container reboot or redeploy. 

By deploying TrustVault via **Coolify on your own VPS**:
1. **Persistent Hardware Storage:** Document files and PostgreSQL data are stored directly on persistent Docker volumes (`vault_storage` and `postgres_data`) on your VPS's SSD. **Files are never deleted across restarts, updates, or redeployments.**
2. **Zero Extra Cloud Volume Costs:** No separate \$7+/month disk add-on fees.
3. **Automatic SSL & Reverse Proxy:** Coolify's built-in Traefik proxy automatically issues and renews free Let's Encrypt SSL certificates.
4. **Unified Single-Origin Proxy:** The Nginx frontend automatically reverse-proxies `/api/` traffic directly to the backend over the internal Docker network. Zero CORS configuration needed.
5. **Full Privacy & Data Sovereignty:** Confidential documents never leave your server.

---

## 1. Prerequisites

- A Linux server (Ubuntu 22.04 / 24.04 LTS or Debian 12 recommended).
- Minimum specs: 2 CPU cores, 2 GB RAM (e.g. Hetzner Cloud CX22 at ~€4/mo, DigitalOcean \$6/mo, or AWS EC2 `t3.small`).
- A domain or subdomain pointing to your VPS IP address (e.g. `vault.yourcompany.com`).

---

## 2. Step 1: Install Coolify on Your VPS

SSH into your server and run the official Coolify installation script:

```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash
```

Once installation finishes (takes 1–2 minutes):
1. Open your browser and navigate to:
   ```text
   http://<YOUR_VPS_IP>:8000
   ```
2. Create your administrative account.

---

## 3. Step 2: Create TrustVault Resource in Coolify

1. In the Coolify dashboard, navigate to **Projects** $\rightarrow$ click **+ Add Project**.
2. Click **+ Add Resource** $\rightarrow$ select **Public Repository** (or **GitHub App** if private).
3. Enter the repository URL:
   ```text
   https://github.com/Narendra-1715/Trust_Vault.git
   ```
4. Set **Branch**: `main`.
5. Under **Build Pack**, select **Docker Compose**.
6. Set **Custom Docker Compose File Location**:
   ```text
   docker-compose.coolify.yml
   ```

---

## 4. Step 3: Configure Environment Variables

Click the **Environment Variables** tab for your TrustVault resource in Coolify and configure:

| Variable | Recommended Value | Purpose |
| :--- | :--- | :--- |
| `SECRET_KEY` | Generate with `openssl rand -hex 32` | JWT cryptographic signing key |
| `POSTGRES_USER` | `trustvault_admin` | Database username |
| `POSTGRES_PASSWORD` | Strong generated password | Database password |
| `POSTGRES_DB` | `trustvault_prod` | Production database name |
| `AI_PROVIDER` | `gemini` (or `mock`) | AI engine for access policy suggestions |
| `GEMINI_API_KEY` | `AIzaSy...` (optional) | Google Gemini API key |
| `AI_MODEL` | `gemini-2.5-flash` | Gemini model name |
| `ENVIRONMENT` | `production` | Enables production security constraints |
| `DEBUG` | `false` | Disables verbose debugging |

---

## 5. Step 6: Configure Domain & SSL

1. In the Coolify resource configuration, locate the **frontend** service.
2. In the **Domains** (or FQDN) field, enter your domain with `https://`:
   ```text
   https://vault.yourcompany.com
   ```
3. Coolify will automatically configure Traefik to request and install a Let's Encrypt SSL certificate for this domain.

---

## 6. Step 5: Deploy TrustVault

1. Click **Deploy** in the top-right corner of Coolify.
2. Coolify will:
   - Clone the TrustVault repository.
   - Build the backend container (`python:3.12-slim`).
   - Run Alembic database migrations (`alembic upgrade head`).
   - Build the frontend container with Vite and package it in Nginx.
   - Initialize persistent Docker named volumes:
     * `postgres_data`: holds PostgreSQL database files.
     * `vault_storage`: holds private uploaded document files (`/app/data/vault_storage`).
   - Start all services and wire up SSL routing.

---

## 7. Storage Durability Verification

Once deployed on Coolify, verify storage persistence across restarts:

1. Log in to `https://vault.yourcompany.com` as an owner.
2. Upload a confidential document.
3. In Coolify, click **Restart** (or trigger a redeploy).
4. Refresh `https://vault.yourcompany.com` and click **Download** or **Secure Preview**.
5. The document will load and download with exact byte parity and matching SHA-256 checksum because the Docker volume `vault_storage` is physically hosted on your server's SSD.

---

## 8. Backup and Restore

Coolify includes built-in automated backups:
- In Coolify, navigate to the `postgres` service $\rightarrow$ **Backups** tab.
- Enable automated daily database backups (retained locally or pushed to S3/Cloudflare R2).
- To backup physical document files, archive the host volume:
  ```bash
  tar -czvf /backup/vault_storage_$(date +%F).tar.gz /var/lib/docker/volumes/*vault_storage*/_data
  ```
