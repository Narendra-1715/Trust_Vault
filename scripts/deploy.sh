#!/bin/bash
set -e

# ==============================================================================
# TrustVault Production Deployment Automation Script
# ==============================================================================

echo "=================================================="
echo "    TrustVault Production Deployment Engine       "
echo "=================================================="

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed. Please install Docker before deploying."
    exit 1
fi

# Generate production .env if not exists
if [ ! -f .env ]; then
    echo "[INIT] Generating production .env file..."
    cp .env.production.example .env
    
    # Generate secure random secret key
    RANDOM_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
    RANDOM_DB_PASS=$(python3 -c "import secrets; print(secrets.token_hex(16))" 2>/dev/null || openssl rand -hex 16)
    
    sed -i "s/generate_a_random_64_character_hex_string_here_for_production/$RANDOM_SECRET/g" .env
    sed -i "s/replace_with_a_strong_database_password_2026/$RANDOM_DB_PASS/g" .env
    echo "[INIT] Generated random SECRET_KEY and POSTGRES_PASSWORD."
fi

echo "[DEPLOY] Building and starting production containers..."
docker compose -f docker-compose.prod.yml up --build -d

echo "[VERIFY] Waiting for services to become healthy..."
sleep 8

# Check backend health
if command -v curl &> /dev/null; then
    echo "[VERIFY] Probing API health endpoint..."
    curl -sf http://localhost:8000/api/v1/health || true
fi

echo ""
echo "=================================================="
echo "   TrustVault Deployed Successfully!             "
echo "   - Web UI: http://localhost                    "
echo "   - API Docs: http://localhost:8000/docs        "
echo "   - API Health: http://localhost:8000/api/v1/health"
echo "=================================================="
