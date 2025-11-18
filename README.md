# Coralogix Alert Generator

Automatically generate and deploy Coralogix Alert CRDs from PrometheusRule files.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Deploy Alerts

```bash
python scripts/deploy_alerts.py --prometheus-file your-prometheus-rules.yaml
```

### 3. Verify Deployment

```bash
kubectl get alerts.coralogix.com -A
```

**That's it!** Your alerts are now deployed and synced to Coralogix.

## 📋 Prerequisites

- **Python 3.6+** - [Download](https://www.python.org/downloads/)
- **kubectl** - [Install Guide](https://kubernetes.io/docs/tasks/tools/)
- **Coralogix Operator** - Must be installed in your Kubernetes cluster

### Verify Prerequisites

```bash
# Check Python
python3 --version

# Check kubectl
kubectl version --client

# Check operator
kubectl get pods -n coralogix-operator
```

## 📖 Usage Examples

### Deploy from Specific File

```bash
python scripts/deploy_alerts.py --prometheus-file examples/test-opsgenie-alerts.yaml
```

### Dry-Run (Validate Only)

Test without deploying:

```bash
python scripts/deploy_alerts.py --prometheus-file your-rules.yaml --dry-run
```

### Deploy All PrometheusRules

Scan and deploy all PrometheusRule files in current directory:

```bash
python scripts/deploy_alerts.py
```

### Override Namespace

Deploy all alerts to a specific namespace:

```bash
python scripts/deploy_alerts.py --prometheus-file your-rules.yaml --namespace my-namespace
```

### Continue on Error

Continue deploying even if some alerts fail:

```bash
python scripts/deploy_alerts.py --prometheus-file your-rules.yaml --continue-on-error
```

## 🎯 What This Does

1. **Generates** Alert CRDs from your PrometheusRule files
2. **Converts** Prometheus template syntax (`{{ $labels.pod }}`) to Tera syntax (`{{ alert.groups[0].keyValues.pod }}`)
3. **Adds** required labels (`routing.group: main` in `spec.entityLabels`)
4. **Deploys** alerts to your Kubernetes cluster
5. **Syncs** alerts to Coralogix platform

## 📁 Project Structure

```
coralogix-alert-generator/
├── scripts/
│   ├── gen_alerts.py          # Generator script
│   ├── deploy_alerts.py       # Deployment script
│   └── tests/
│       └── test_gen_alerts.py # Unit tests
├── examples/
│   └── test-opsgenie-alerts.yaml  # Example PrometheusRule
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🔧 Template Conversion

The script automatically converts Prometheus templates to Tera:

**Before (Prometheus)**:
```yaml
description: 'Pod {{ $labels.pod }} in namespace {{ $labels.namespace }}'
```

**After (Tera)**:
```yaml
description: 'Pod {{ alert.groups[0].keyValues.pod }} in namespace {{ alert.groups[0].keyValues.namespace }}'
```

## ✅ Required Label

All generated alerts include:
```yaml
spec:
  entityLabels:
    routing.group: main
```

This is required for routing alerts to the correct notification group.

## 🎨 Priority Mapping

Severity from PrometheusRule labels maps to priority:
- `critical` → `p1`
- `error` → `p2`
- `warning` → `p3`
- `info` → `p4`
- `low` → `p5`
- (default) → `p4`

## 🐛 Troubleshooting

### kubectl Not Found

```bash
# macOS
brew install kubectl

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

### Python Dependencies Missing

```bash
pip install -r requirements.txt
```

### Operator Not Running

```bash
# Check operator status
kubectl get pods -n coralogix-operator

# View operator logs
kubectl logs -n coralogix-operator -l app=coralogix-operator --tail=100
```

### Alerts Not Syncing

```bash
# Check alert status
kubectl get alert <alert-name> -n <namespace> -o yaml | grep -A 10 status

# Check operator logs for errors
kubectl logs -n coralogix-operator -l app=coralogix-operator --tail=100 | grep -i error
```

## 📚 Example Workflow

```bash
# 1. Clone this repository
git clone <repository-url>
cd coralogix-alert-generator

# 2. Install dependencies
pip install -r requirements.txt

# 3. Test with example file (dry-run)
python scripts/deploy_alerts.py --prometheus-file examples/test-opsgenie-alerts.yaml --dry-run

# 4. Deploy for real
python scripts/deploy_alerts.py --prometheus-file examples/test-opsgenie-alerts.yaml

# 5. Verify deployment
kubectl get alerts.coralogix.com -A
```

## 🔍 Verify Deployment

### List All Alerts

```bash
kubectl get alerts.coralogix.com -A
```

### Check Specific Alert

```bash
kubectl get alert <alert-name> -n <namespace> -o yaml
```

### Check Alert Status

```bash
kubectl get alert <alert-name> -n <namespace> -o jsonpath='{.status.printableStatus}'
# Should show: RemoteSynced
```

### Get Coralogix Alert ID

```bash
kubectl get alert <alert-name> -n <namespace> -o jsonpath='{.status.id}'
```

## 💡 Tips

- **Always test with `--dry-run` first** to validate before deploying
- **Use `--continue-on-error`** for large deployments to see all errors
- **Check generated files** in `generated/alerts/` to review before deploying
- **Monitor operator logs** if alerts aren't syncing
- **Use `--wait-timeout 0`** for faster deployment if you don't need to wait for sync

## 📝 License

[Add your license here]

## 🤝 Support

For issues or questions, please contact your Coralogix support representative.

