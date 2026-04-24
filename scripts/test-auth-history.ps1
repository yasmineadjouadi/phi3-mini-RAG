# Test login + GET /history/ (use one line for Invoke-RestMethod in console)
$ErrorActionPreference = "Stop"
$base = "http://127.0.0.1:8000"

$loginBody = '{"email":"cboussoura","password":"Passw0rd@2o26"}'
$response = Invoke-RestMethod -Uri "$base/auth/login" -Method POST -ContentType "application/json; charset=utf-8" -Body $loginBody

$token = $response.access_token
if (-not $token) { throw "Pas de access_token dans la reponse login" }

$headers = @{}
$headers["Authorization"] = "Bearer " + $token

Invoke-RestMethod -Uri "$base/history/" -Headers $headers -Method GET
