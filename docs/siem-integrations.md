# SIEM And Alert Integrations

Interlock can dispatch scan results to Slack, Datadog, Splunk HEC, Elastic, PagerDuty, Sumo Logic, or a generic webhook. Dispatch errors are logged and do not break the scan path.

---

## Supported Providers

| Provider | Config key | Notes |
|---|---|---|
| Slack | `slack` | Sends a Slack-compatible webhook message. |
| Datadog | `datadog` | Sends logs to Datadog HTTP intake. |
| Splunk HEC | `splunk_hec` | Sends events to Splunk HTTP Event Collector. |
| Elastic | `elastic` | Sends documents to an Elastic index. |
| PagerDuty | `pagerduty` | Triggers incidents for high/critical results. |
| Sumo Logic | `sumologic` | Sends JSON to an HTTP source URL. |
| Webhook | `webhook` | Sends generic JSON to a configured endpoint. |

---

## Slack Example

```json
{
  "siem_configs": [
    {
      "provider": "slack",
      "webhook_url": "https://hooks.slack.com/services/...",
      "min_severity": "HIGH"
    }
  ]
}
```

---

## Datadog Example

```json
{
  "siem_configs": [
    {
      "provider": "datadog",
      "api_key": "<YOUR_DATADOG_API_KEY>",
      "region": "us",
      "source": "interlock",
      "min_severity": "MEDIUM"
    }
  ]
}
```

---

## Splunk HEC Example

```json
{
  "siem_configs": [
    {
      "provider": "splunk_hec",
      "url": "https://splunk.example.com:8088",
      "token": "<YOUR_SPLUNK_HEC_TOKEN>",
      "verify_ssl": true,
      "min_severity": "LOW"
    }
  ]
}
```

---

## Elastic Example

```json
{
  "siem_configs": [
    {
      "provider": "elastic",
      "url": "https://elastic.example.com",
      "api_key": "<YOUR_ELASTIC_API_KEY>",
      "index": "interlock-logs",
      "verify_ssl": true
    }
  ]
}
```

---

## Generic Webhook Example

```json
{
  "siem_configs": [
    {
      "provider": "webhook",
      "url": "https://security.example.com/interlock-alerts",
      "headers": {"Authorization": "Bearer <YOUR_WEBHOOK_BEARER_TOKEN>"},
      "min_severity": "LOW"
    }
  ]
}
```

---

## Test A Provider

```bash
curl -X POST http://localhost:8001/siem/test \
  -H "x-api-key: <YOUR_INTERLOCK_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "slack",
    "config": {
      "webhook_url": "https://hooks.slack.com/services/..."
    }
  }'
```

---

## Enterprise Note

For a pilot, start with Slack or generic webhook. For a production security team, route high and critical decisions to SIEM and incident response, then keep low/medium events in audit logs for investigation.
