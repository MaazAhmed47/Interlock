# Interlock — Production Deployment Guide

Enterprise-grade Kubernetes deployment for Interlock with full HA, auto-scaling, security hardening, and observability.

---

## Quick Start

### Option 1 — Helm (Recommended for Production)

```bash
# Add helm repo
helm repo add llm-firewall https://charts.llmfirewall.dev
helm repo update

# Install with default values
helm install firewall llm-firewall/llm-firewall \
  --namespace llm-firewall \
  --create-namespace \
  --set secrets.groqApiKey=$GROQ_API_KEY \
  --set secrets.openaiApiKey=$OPENAI_API_KEY

# Or install from local chart
helm install firewall ./helm \
  --namespace llm-firewall \
  --create-namespace \
  --values ./helm/values.yaml
```

### Option 2 — Docker Compose (Dev/Staging)

```bash
# Set environment variables
cp .env.example .env
# Edit .env with your API keys

# Start
docker-compose up -d

# With monitoring stack
docker-compose --profile monitoring up -d
```

### Option 3 — Raw Kubernetes Manifests

```bash
kubectl apply -f manifests/
```

---

## Production Configuration

### High Availability Setup

```bash
helm upgrade firewall ./helm \
  --set replicaCount=5 \
  --set autoscaling.minReplicas=5 \
  --set autoscaling.maxReplicas=50 \
  --set podDisruptionBudget.minAvailable=3 \
  --set persistence.size=50Gi
```

### With External Secrets (Vault/AWS Secrets Manager)

```bash
helm upgrade firewall ./helm \
  --set externalSecrets.enabled=true \
  --set externalSecrets.secretStore.name=vault-backend
```

### Multi-Region Setup

```bash
# Region 1 — US East
helm install firewall-us ./helm \
  --set ingress.hosts[0].host=us.api.llmfirewall.dev \
  --namespace firewall-us

# Region 2 — EU West
helm install firewall-eu ./helm \
  --set ingress.hosts[0].host=eu.api.llmfirewall.dev \
  --namespace firewall-eu
```

---

## Security Features

✓ **Non-root containers** (UID 1000)
✓ **Read-only root filesystem**
✓ **Dropped capabilities** (ALL)
✓ **Seccomp profile** (RuntimeDefault)
✓ **Network policies** (zero-trust)
✓ **TLS termination** (cert-manager)
✓ **Rate limiting** (nginx ingress)
✓ **Pod security standards**

---

## Auto-Scaling

The HPA scales pods based on:
- **CPU utilization** (target 70%)
- **Memory utilization** (target 80%)
- **Scale-up:** Aggressive (100% in 30s)
- **Scale-down:** Conservative (50% in 5min stabilization)

Range: 3–20 replicas by default

---

## Monitoring

### Prometheus Metrics
Available at `:8000/metrics`:
- Request rate
- Threat detection rate
- Layer hit distribution
- Latency percentiles
- Error rates

### Grafana Dashboard
Pre-built dashboard with:
- Real-time scan rate
- Threat type breakdown
- Geographic threat distribution
- Per-API-key analytics
- SLA compliance tracking

---

## Disaster Recovery

### Backup Strategy
```bash
# Backup learned patterns + history
kubectl exec -n llm-firewall <pod-name> -- \
  tar czf - /app/data | gzip > firewall-backup-$(date +%Y%m%d).tar.gz
```

### Restore
```bash
kubectl exec -n llm-firewall <pod-name> -- \
  tar xzf - -C /app/data < firewall-backup.tar.gz
```

---

## Troubleshooting

### Pods not starting
```bash
kubectl describe pod -n llm-firewall <pod-name>
kubectl logs -n llm-firewall <pod-name> --previous
```

### High memory usage
```bash
kubectl top pods -n llm-firewall
# Scale resources in values.yaml
```

### Connection issues
```bash
# Test internal service
kubectl run test --rm -it --image=curlimages/curl --restart=Never -- \
  curl http://firewall.llm-firewall:80/health
```

---

## Cost Optimization

For non-production environments:
```yaml
replicaCount: 1
autoscaling:
  enabled: false
resources:
  requests:
    cpu: 100m
    memory: 128Mi
persistence:
  size: 1Gi
```

---

## Compliance Mode

For SOC-2/HIPAA/GDPR compliance:
```bash
helm upgrade firewall ./helm \
  --set podSecurityContext.fsGroup=1000 \
  --set logging.format=json \
  --set monitoring.enabled=true \
  --set persistence.enabled=true \
  --set ingress.tls[0].secretName=llm-firewall-tls
```

---

## Support

- 📚 Docs: https://docs.llmfirewall.dev
- 🛠 Enterprise Support: enterprise@llmfirewall.dev
- 💬 Community: https://discord.gg/llmfirewall
- 🐛 Issues: https://github.com/llmfirewall/llm-firewall
