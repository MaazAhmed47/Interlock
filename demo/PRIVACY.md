# Privacy and Data Handling

Interlock can run in two logging modes:

## Metadata-only mode (recommended for sensitive environments)
Audit logs store only:
- Agent role
- Tool name
- Decision (allow/block/shadow)
- Risk score
- Layer caught
- Timestamp

Prompt content and response data are NOT stored.

## Full audit mode
Stores the above plus a preview of the prompt (first 120 chars) for forensic analysis.

## Self-hosted option
Deploy Interlock in your own VPC. Data never leaves your infrastructure.
Helm chart included for Kubernetes deployment.

For pilot deployments, metadata-only mode is the default.
