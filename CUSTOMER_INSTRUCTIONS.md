# Customer Instructions

## How to Use This Repository

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd coralogix-alert-generator
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Deploy Your Alerts

```bash
python scripts/deploy_alerts.py --prometheus-file your-prometheus-rules.yaml
```

**That's it!** Your alerts are now deployed and synced to Coralogix.

## Prerequisites

Before using this tool, ensure you have:

1. **Python 3.6+** installed
2. **kubectl** configured and connected to your Kubernetes cluster
3. **Coralogix Operator** installed in your cluster

See `INSTALL.md` for detailed installation instructions.

## Quick Test

Test with the included example:

```bash
# Dry-run (safe, no changes)
python scripts/deploy_alerts.py --prometheus-file examples/test-opsgenie-alerts.yaml --dry-run

# Deploy for real
python scripts/deploy_alerts.py --prometheus-file examples/test-opsgenie-alerts.yaml
```

## Verify Deployment

```bash
# List all alerts
kubectl get alerts.coralogix.com -A

# Check specific alert status
kubectl get alert <alert-name> -n <namespace> -o jsonpath='{.status.printableStatus}'
```

## Need Help?

- See `README.md` for detailed documentation
- See `INSTALL.md` for installation help
- Contact your Coralogix support representative

