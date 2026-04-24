# POST /auth/create-user (superadmin uniquement)
# Usage: .\scripts\create-user.ps1
#    ou: .\scripts\create-user.ps1 -Email "alice@test.local" -Password "MonMotDePasse1!"
param(
    [string]$Email = "testuser@example.local",
    [string]$Password = "Passw0rd@2o26",
    [string]$Base = "http://127.0.0.1:8000",
    [string]$AdminEmail = "cboussoura",
    [string]$AdminPassword = "Passw0rd@2o26"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

$loginBody = (@{ email = $AdminEmail; password = $AdminPassword } | ConvertTo-Json -Compress)
$login = Invoke-RestMethod -Uri "$Base/auth/login" -Method POST -ContentType "application/json; charset=utf-8" -Body $loginBody
$tok = $login.access_token
if (-not $tok) { throw "Login admin impossible" }

$headers = @{ Authorization = "Bearer $tok" }
$newBody = (@{ email = $Email; password = $Password } | ConvertTo-Json -Compress)
$result = Invoke-RestMethod -Uri "$Base/auth/create-user" -Method POST -ContentType "application/json; charset=utf-8" -Body $newBody -Headers $headers
Write-Host "OK utilisateur cree:" -ForegroundColor Green
$result | ConvertTo-Json
