Write-Host "`n[TEST 1] Clean prompt - should PASS" -ForegroundColor Cyan
$body = '{"prompt":"Summarize this support ticket politely"}'
Invoke-RestMethod `
  -Method POST `
  -Uri "https://interlock.onrender.com/scan" `
  -Headers @{ "x-api-key" = "lf-dev-key-456" } `
  -ContentType "application/json" `
  -Body $body | ConvertTo-Json
