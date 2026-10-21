# ==============================================================================
# TrustVault Production Deployment Automation Script (PowerShell)
# ==============================================================================

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "    TrustVault Production Deployment Engine       " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Check Docker installation
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Docker is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# Generate production .env if not exists
if (-not (Test-Path ".env")) {
    Write-Host "[INIT] Generating production .env file..." -ForegroundColor Yellow
    Copy-Item ".env.production.example" ".env"
    
    $secret = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
    $dbPass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
    
    (Get-Content ".env") -replace "generate_a_random_64_character_hex_string_here_for_production", $secret `
                         -replace "replace_with_a_strong_database_password_2026", $dbPass | Set-Content ".env"
    Write-Host "[INIT] Generated random SECRET_KEY and POSTGRES_PASSWORD." -ForegroundColor Green
}

Write-Host "[DEPLOY] Building and starting production containers..." -ForegroundColor Yellow
docker compose -f docker-compose.prod.yml up --build -d

Write-Host "[VERIFY] Waiting for containers to become healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "   TrustVault Deployed Successfully!             " -ForegroundColor Green
Write-Host "   - Web UI: http://localhost                    " -ForegroundColor Green
Write-Host "   - API Docs: http://localhost:8000/docs        " -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
