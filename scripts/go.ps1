# 1) init_db / migrations MySQL  2) Si API up: login + GET /history/
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

$py = Join-Path (Get-Location) "venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

Write-Host ">> init_db() ..." -ForegroundColor Cyan
& $py -c "from database.db import init_db; init_db(); print('OK')"

try {
    Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -UseBasicParsing -TimeoutSec 2 | Out-Null
} catch {
    Write-Host ">> API down - start: uvicorn app:app --reload then run this script again." -ForegroundColor Yellow
    exit 0
}

$base = "http://127.0.0.1:8000"
$body = '{"email":"cboussoura","password":"Passw0rd@2o26"}'

Write-Host ">> POST /auth/login ..." -ForegroundColor Cyan
$login = Invoke-RestMethod -Uri "$base/auth/login" -Method POST -ContentType "application/json; charset=utf-8" -Body $body
$tok = $login.access_token
if (-not $tok) { throw "Login sans access_token" }

Write-Host ">> GET /history/ ..." -ForegroundColor Cyan
$uri = "$base/history/"
try {
    $resp = Invoke-WebRequest -Uri $uri -Method GET -Headers @{ Authorization = "Bearer $tok" } -UseBasicParsing
    Write-Host ("Status: " + $resp.StatusCode) -ForegroundColor Green
    Write-Host $resp.Content
} catch {
    Write-Host ($_.Exception.Message) -ForegroundColor Red
    if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message -ForegroundColor Yellow }
    exit 1
}
