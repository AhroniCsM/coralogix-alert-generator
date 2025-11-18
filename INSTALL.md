# Installation Guide

## Quick Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd coralogix-alert-generator

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Verify installation
python scripts/deploy_alerts.py --help
```

## Detailed Installation

### Step 1: Install Python 3.6+

**macOS:**
```bash
brew install python3
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip
```

**Windows:**
Download from [python.org](https://www.python.org/downloads/)

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install pyyaml
```

### Step 3: Install kubectl

**macOS:**
```bash
brew install kubectl
```

**Linux:**
```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

**Windows:**
Download from [kubernetes.io](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/)

### Step 4: Verify Installation

```bash
# Check Python
python3 --version
# Should show: Python 3.6.x or higher

# Check pip
pip --version

# Check kubectl
kubectl version --client

# Check cluster access
kubectl get nodes
```

### Step 5: Verify Coralogix Operator

```bash
# Check if operator is installed
kubectl get pods -n coralogix-operator

# Should see something like:
# NAME                                  READY   STATUS    RESTARTS   AGE
# cxo-coralogix-operator-xxxxx-xxxxx   1/1     Running   0          1d
```

If operator is not installed, see: [Coralogix Operator Installation](https://github.com/coralogix/coralogix-kubernetes-operator)

## Test Installation

```bash
# Test with example file (dry-run)
python scripts/deploy_alerts.py --prometheus-file examples/test-opsgenie-alerts.yaml --dry-run
```

If you see "✓ Validated" for all alerts, installation is successful!

## Troubleshooting

### Python Not Found

```bash
# Try python3 instead of python
python3 scripts/deploy_alerts.py --help
```

### Permission Denied

```bash
# Make scripts executable
chmod +x scripts/*.py
```

### Module Not Found

```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

