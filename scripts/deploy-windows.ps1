# Vo!d Windows Deploy Script
# Requires: Docker Desktop for Windows, PowerShell 5+
# Run as Administrator for WFP driver support

param(
    [string]$Upstream = "http://localhost:3000",
    [switch]$SkipEbpf
)

Write-Host "==> Vo!d Windows Deployment" -ForegroundColor Cyan
Write-Host "    Upstream: $Upstream"
Write-Host ""

# Check Docker Desktop
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker Desktop is required. Download from https://www.docker.com/products/docker-desktop"
    exit 1
}

# Check Docker is running
$dockerStatus = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker Desktop is not running. Please start it."
    exit 1
}

Write-Host "==> Docker Desktop detected" -ForegroundColor Green

# Note on eBPF
Write-Host ""
Write-Host "  NOTE: eBPF (kernel-level XDP) is Linux-only." -ForegroundColor Yellow
Write-Host "  On Windows, Vo!d runs in software-only mode:" -ForegroundColor Yellow
Write-Host "   - SYN flood protection via WFP (Windows Filtering Platform)" -ForegroundColor Yellow
Write-Host "   - All other detection layers fully functional" -ForegroundColor Yellow
Write-Host "   - ~5-10% higher latency vs Linux eBPF mode" -ForegroundColor Yellow
Write-Host ""

# Generate secrets
if (-not (Test-Path ".env")) {
    Write-Host "==> Generating secrets..."
    $secret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | % {[char]$_})
    $grafanaPass = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
    @"
CHALLENGE_SECRET=$secret
GRAFANA_PASSWORD=$grafanaPass
UPSTREAM=$Upstream
VOID_MODE=windows
"@ | Out-File -FilePath ".env" -Encoding utf8
    Write-Host "    .env created" -ForegroundColor Green
}

# Create model directory
New-Item -ItemType Directory -Force -Path "models" | Out-Null

# Build and start (without eBPF container on Windows)
Write-Host "==> Building Vo!d containers..."
docker compose -f docker/docker-compose.windows.yml build

Write-Host "==> Starting Vo!d..."
docker compose -f docker/docker-compose.windows.yml up -d

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Vo!d is running!" -ForegroundColor Cyan  
Write-Host "============================================"
Write-Host ""
Write-Host "  Edge Proxy:   http://localhost:8080" -ForegroundColor White
Write-Host "  Dashboard:    http://localhost:3001" -ForegroundColor White
Write-Host "  Prometheus:   http://localhost:9090" -ForegroundColor White
Write-Host ""
Write-Host "  Logs:  docker compose -f docker/docker-compose.windows.yml logs -f void-edge"
Write-Host "  Stop:  docker compose -f docker/docker-compose.windows.yml down"
