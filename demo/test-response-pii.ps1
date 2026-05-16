Write-Host "`n[TEST 4] PII in response — should BLOCK" -ForegroundColor Red
$body = '{"prompt":"What is the SSN for customer 123-45-6789?"}'
Invoke-RestMethod `
  -Method POST `
  -Uri "https://interlock.onrender.com/scan" `
  -Headers @{ "x-api-key" = "lf-dev-key-456" } `
  -ContentType "application/json" `
  -Body $body | ConvertTo-Json
