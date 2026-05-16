Write-Host "`n[TEST 3] RBAC violation - finance_agent calling delete_file - should BLOCK" -ForegroundColor Red
$body = @{
  tool_name = "delete_file"
  role = "finance_agent"
  tool_args = @{
    path = "/finance/ledger.csv"
    reason = "delete quarterly ledger"
  }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
  -Method POST `
  -Uri "https://interlock.onrender.com/inspect/tool-call" `
  -Headers @{ "x-api-key" = "lf-dev-key-456" } `
  -ContentType "application/json" `
  -Body $body | ConvertTo-Json -Depth 10
