#!/bin/bash
# ============================================================================
# Interlock - Kubernetes Install Script
# ============================================================================

set -e

NAMESPACE="${NAMESPACE:-interlock}"
RELEASE_NAME="${RELEASE_NAME:-interlock}"
ENVIRONMENT="${ENVIRONMENT:-dev}"

echo "Interlock Kubernetes Installer"
echo "=========================="
echo "Namespace:    $NAMESPACE"
echo "Release:      $RELEASE_NAME"
echo "Environment:  $ENVIRONMENT"
echo ""

# Check kubectl
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

# Check helm
if ! command -v helm &> /dev/null; then
    echo "❌ helm not found. Install: https://helm.sh/docs/intro/install/"
    exit 1
fi

# Check cluster connection
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster"
    exit 1
fi

echo "✓ Prerequisites OK"
echo ""

# Create namespace
echo "→ Creating namespace..."
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Install based on environment
case $ENVIRONMENT in
  production)
    echo "→ Installing PRODUCTION configuration..."
    helm upgrade --install $RELEASE_NAME ./helm \
      --namespace $NAMESPACE \
      --values ./helm/values.yaml \
      --set autoscaling.minReplicas=3 \
      --set autoscaling.maxReplicas=20 \
      --set persistence.enabled=true \
      --set monitoring.enabled=true \
      --wait
    ;;
  staging)
    echo "→ Installing STAGING configuration..."
    helm upgrade --install $RELEASE_NAME ./helm \
      --namespace $NAMESPACE \
      --values ./helm/values.yaml \
      --set replicaCount=2 \
      --set autoscaling.minReplicas=2 \
      --set autoscaling.maxReplicas=5 \
      --wait
    ;;
  dev)
    echo "→ Installing DEV configuration..."
    helm upgrade --install $RELEASE_NAME ./helm \
      --namespace $NAMESPACE \
      --values ./helm/values.yaml \
      --set replicaCount=1 \
      --set autoscaling.enabled=false \
      --set persistence.enabled=false \
      --set ingress.enabled=false \
      --wait
    ;;
  *)
    echo "❌ Unknown environment: $ENVIRONMENT (use: production|staging|dev)"
    exit 1
    ;;
esac

echo ""
echo "✓ Installation complete!"
echo ""
echo "Next steps:"
echo "  kubectl get pods -n $NAMESPACE"
echo "  kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=interlock -f"
echo ""
