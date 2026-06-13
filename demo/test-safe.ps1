$ApiKey = $env:INTERLOCK_API_KEY
if (-not $ApiKey) { Write-Error "Set INTERLOCK_API_KEY to a key you mint via POST /admin/tokens -> POST /admin/keys (see demo/README.md)."; exit 1 }

Write-Host "`n[TEST 1] Clean prompt - should PASS" -ForegroundColor Cyan
$body = '{"prompt":"Summarize this support ticket politely"}'
Invoke-RestMethod `
  -Method POST `
  -Uri "https://interlock.onrender.com/scan" `
  -Headers @{ "x-api-key" = $ApiKey } `
  -ContentType "application/json" `
  -Body $body | ConvertTo-Json
