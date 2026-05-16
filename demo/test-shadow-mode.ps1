Write-Host "`n[TEST 5] Shadow mode — observe without blocking" -ForegroundColor Yellow
Write-Host "In shadow mode, threats are logged but NOT blocked." -ForegroundColor Yellow
$body = '{"prompt":"SELECT * FROM users; DROP TABLE users--"}'
$result = Invoke-RestMethod `
  -Method POST `
  -Uri "https://interlock.onrender.com/scan" `
  -Headers @{ "x-api-key" = "lf-dev-key-456" } `
  -ContentType "application/json" `
  -Body $body
$shadow = [PSCustomObject]@{
  agent_role      = "finance_agent"
  tool            = "query_warehouse"
  decision        = "would_block"
  reason          = $result.reason
  mode            = "shadow"
  threat_type     = $result.threat_type
  layer_caught    = $result.layer_caught
  risk_score      = $result.risk_score
  confidence      = $result.confidence
  suggested_action = "block in production"
  timestamp       = (Get-Date -Format "o")
}
Write-Host "`nShadow mode audit log entry:" -ForegroundColor Yellow
$shadow | ConvertTo-Json
