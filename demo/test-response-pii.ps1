Write-Host "`n[TEST 4] PII in output/response - should BLOCK" -ForegroundColor Red
$body = @{
  prompt = "Tool response: customer_email=demo@example.com ssn=XXX-XX-XXXX api_key=sk-demo-redacted"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method POST `
  -Uri "https://interlock.onrender.com/scan/output" `
  -Headers @{ "x-api-key" = "lf-dev-key-456" } `
  -ContentType "application/json" `
  -Body $body | ConvertTo-Json -Depth 10
