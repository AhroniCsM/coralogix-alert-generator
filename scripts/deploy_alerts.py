#!/usr/bin/env python3
"""
Production-ready Alert Deployment Script

This script generates Alert CRDs from PrometheusRule files and deploys them
to Kubernetes one by one, checking for errors and providing a comprehensive summary.

Usage:
    python scripts/deploy_alerts.py [--input-dir DIR] [--prometheus-file FILE] [--dry-run] [--namespace NAMESPACE]

Options:
    --input-dir DIR         Directory to search for PrometheusRule YAML files (default: repo root)
    --prometheus-file FILE  Specific PrometheusRule file to process (overrides --input-dir)
    --output-dir DIR        Directory to write generated Alert CRDs (default: generated/alerts)
    --dry-run              Generate alerts but don't deploy them
    --namespace NAMESPACE  Override namespace for all alerts (optional)
    --continue-on-error    Continue deploying even if some alerts fail
    --wait-timeout SECONDS Timeout in seconds to wait for alert sync (default: 60)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import generator functions
sys.path.insert(0, str(Path(__file__).parent))
from gen_alerts import (
    find_prometheus_rules,
    parse_prometheus_rules,
    generate_alerts_from_prometheus_rules,
    write_alert_yaml,
)


@dataclass
class DeploymentResult:
    """Result of deploying a single alert."""
    alert_name: str
    namespace: str
    file_path: Path
    status: str  # 'success', 'failed', 'skipped', 'pending'
    error: Optional[str] = None
    alert_id: Optional[str] = None
    sync_status: Optional[str] = None
    deployment_time: Optional[float] = None


@dataclass
class DeploymentSummary:
    """Summary of deployment operation."""
    total_alerts: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    pending: int = 0
    results: List[DeploymentResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Get deployment duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def success_rate(self) -> float:
        """Get success rate as percentage."""
        if self.total_alerts == 0:
            return 0.0
        return (self.successful / self.total_alerts) * 100


def run_kubectl_command(args: List[str], capture_output: bool = True) -> Tuple[int, str, str]:
    """
    Run a kubectl command and return the result.
    
    Args:
        args: Command arguments (without 'kubectl')
        capture_output: Whether to capture stdout/stderr
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    cmd = ['kubectl'] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=300,  # 5 minute timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, '', f"Command timed out: {' '.join(cmd)}"
    except Exception as e:
        return 1, '', f"Error running command: {e}"


def check_kubectl_available() -> bool:
    """Check if kubectl is available."""
    returncode, _, _ = run_kubectl_command(['version', '--client'], capture_output=True)
    return returncode == 0


def check_namespace_exists(namespace: str) -> bool:
    """Check if a namespace exists."""
    returncode, _, _ = run_kubectl_command(['get', 'namespace', namespace], capture_output=True)
    return returncode == 0


def deploy_alert(file_path: Path, dry_run: bool = False) -> DeploymentResult:
    """
    Deploy a single alert CRD to Kubernetes.
    
    Args:
        file_path: Path to Alert CRD YAML file
        dry_run: If True, only validate without deploying
        
    Returns:
        DeploymentResult object
    """
    # Read alert to get name and namespace
    import yaml
    with open(file_path, 'r') as f:
        alert_crd = yaml.safe_load(f)
    
    alert_name = alert_crd['metadata']['name']
    namespace = alert_crd['metadata'].get('namespace', 'default')
    
    result = DeploymentResult(
        alert_name=alert_name,
        namespace=namespace,
        file_path=file_path,
        status='pending',
    )
    
    if dry_run:
        # Validate with kubectl apply --dry-run
        returncode, stdout, stderr = run_kubectl_command([
            'apply',
            '--dry-run=client',
            '-f', str(file_path),
        ])
        
        if returncode == 0:
            result.status = 'success'
            result.sync_status = 'dry-run-validated'
        else:
            result.status = 'failed'
            result.error = stderr or stdout
        return result
    
    # Deploy the alert
    start_time = time.time()
    returncode, stdout, stderr = run_kubectl_command([
        'apply',
        '-f', str(file_path),
    ])
    
    result.deployment_time = time.time() - start_time
    
    if returncode != 0:
        result.status = 'failed'
        result.error = stderr or stdout
        return result
    
    # Wait for alert to sync
    result.status = 'success'
    result.sync_status = 'deployed'
    
    # Try to get alert status
    time.sleep(2)  # Give operator a moment to process
    returncode, stdout, stderr = run_kubectl_command([
        'get',
        'alert',
        alert_name,
        '-n', namespace,
        '-o', 'json',
    ])
    
    if returncode == 0:
        try:
            alert_status = json.loads(stdout)
            status_obj = alert_status.get('status', {})
            result.alert_id = status_obj.get('id')
            result.sync_status = status_obj.get('printableStatus', 'Unknown')
        except (json.JSONDecodeError, KeyError):
            pass
    
    return result


def wait_for_alert_sync(alert_name: str, namespace: str, timeout: int = 60) -> Tuple[bool, Optional[str]]:
    """
    Wait for an alert to sync to RemoteSynced status.
    
    Args:
        alert_name: Name of the alert
        namespace: Namespace of the alert
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (success: bool, status: Optional[str])
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        returncode, stdout, stderr = run_kubectl_command([
            'get',
            'alert',
            alert_name,
            '-n', namespace,
            '-o', 'jsonpath={.status.printableStatus}',
        ])
        
        if returncode == 0 and stdout:
            status = stdout.strip()
            if status == 'RemoteSynced':
                return True, status
            elif 'Error' in status or 'Failed' in status:
                return False, status
        
        time.sleep(2)
    
    return False, None


def generate_and_deploy_alerts(
    input_dir: Optional[Path] = None,
    prometheus_file: Optional[Path] = None,
    output_dir: Path = Path('generated/alerts'),
    dry_run: bool = False,
    namespace_override: Optional[str] = None,
    continue_on_error: bool = False,
    wait_timeout: int = 60,
) -> DeploymentSummary:
    """
    Generate alerts from PrometheusRules and deploy them.
    
    Args:
        input_dir: Directory to search for PrometheusRule files
        prometheus_file: Specific PrometheusRule file to process
        output_dir: Directory to write generated Alert CRDs
        dry_run: If True, only validate without deploying
        namespace_override: Override namespace for all alerts
        continue_on_error: Continue deploying even if some alerts fail
        wait_timeout: Timeout in seconds to wait for alert sync
        
    Returns:
        DeploymentSummary object
    """
    summary = DeploymentSummary(start_time=datetime.now())
    
    print("=" * 80)
    print("Coralogix Alert Deployment Script")
    print("=" * 80)
    print()
    
    # Check prerequisites
    if not dry_run:
        if not check_kubectl_available():
            print("ERROR: kubectl is not available or not configured", file=sys.stderr)
            sys.exit(1)
        print("✓ kubectl is available")
    
    # Generate alerts
    print("\n[1/3] Generating Alert CRDs from PrometheusRules...")
    print("-" * 80)
    
    if prometheus_file:
        if not prometheus_file.exists():
            print(f"ERROR: PrometheusRule file not found: {prometheus_file}", file=sys.stderr)
            sys.exit(1)
        prometheus_rules = parse_prometheus_rules(prometheus_file)
        print(f"✓ Parsed PrometheusRule file: {prometheus_file}")
    else:
        if input_dir is None:
            script_dir = Path(__file__).parent.resolve()
            input_dir = script_dir.parent.resolve()
        
        yaml_files = find_prometheus_rules(input_dir)
        print(f"✓ Found {len(yaml_files)} YAML files to scan")
        
        all_prometheus_rules = []
        for yaml_file in yaml_files:
            rules = parse_prometheus_rules(yaml_file)
            all_prometheus_rules.extend(rules)
        
        prometheus_rules = all_prometheus_rules
        print(f"✓ Found {len(prometheus_rules)} PrometheusRule CRDs")
    
    if not prometheus_rules:
        print("ERROR: No PrometheusRule CRDs found", file=sys.stderr)
        sys.exit(1)
    
    # Generate Alert CRDs
    alerts = generate_alerts_from_prometheus_rules(prometheus_rules)
    print(f"✓ Generated {len(alerts)} Alert CRDs")
    
    if namespace_override:
        # Override namespace in all alerts
        import yaml
        for alert_name, alert_crd in alerts:
            alert_crd['metadata']['namespace'] = namespace_override
    
    # Write generated alerts to output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    alert_files = []
    for alert_name, alert_crd in alerts:
        output_path = output_dir / f"{alert_name}.yaml"
        write_alert_yaml(alert_crd, output_path)
        alert_files.append(output_path)
    
    print(f"✓ Written {len(alert_files)} Alert CRDs to {output_dir}")
    summary.total_alerts = len(alert_files)
    
    if dry_run:
        print("\n[2/3] Validating Alert CRDs (dry-run)...")
    else:
        print("\n[2/3] Deploying Alert CRDs to Kubernetes...")
    print("-" * 80)
    
    # Deploy each alert
    for i, alert_file in enumerate(alert_files, 1):
        print(f"[{i}/{len(alert_files)}] Processing: {alert_file.name}...", end=' ', flush=True)
        
        result = deploy_alert(alert_file, dry_run=dry_run)
        summary.results.append(result)
        
        if result.status == 'success':
            summary.successful += 1
            if dry_run:
                print(f"✓ Validated")
            else:
                print(f"✓ Deployed (status: {result.sync_status or 'pending'})")
                
                # Wait for sync if not dry-run
                if wait_timeout > 0:
                    print(f"  Waiting for sync...", end=' ', flush=True)
                    synced, sync_status = wait_for_alert_sync(
                        result.alert_name,
                        result.namespace,
                        timeout=wait_timeout,
                    )
                    if synced:
                        result.sync_status = sync_status
                        print(f"✓ Synced")
                    else:
                        print(f"⚠ Timeout or error")
        elif result.status == 'failed':
            summary.failed += 1
            print(f"✗ Failed: {result.error[:100] if result.error else 'Unknown error'}")
            if not continue_on_error:
                print("\nERROR: Deployment failed. Use --continue-on-error to continue despite errors.")
                break
        else:
            summary.skipped += 1
            print(f"- Skipped")
    
    summary.end_time = datetime.now()
    
    # Print summary
    print("\n[3/3] Deployment Summary")
    print("=" * 80)
    print_summary(summary, dry_run)
    
    return summary


def print_summary(summary: DeploymentSummary, dry_run: bool = False) -> None:
    """Print deployment summary."""
    print()
    print(f"Total Alerts:     {summary.total_alerts}")
    print(f"Successful:       {summary.successful} ({summary.success_rate:.1f}%)")
    print(f"Failed:           {summary.failed}")
    print(f"Skipped:          {summary.skipped}")
    
    if summary.duration:
        print(f"Duration:         {summary.duration:.1f} seconds")
    
    print()
    
    # Group results by status
    by_status = defaultdict(list)
    for result in summary.results:
        by_status[result.status].append(result)
    
    # Print failed alerts
    if summary.failed > 0:
        print("Failed Alerts:")
        print("-" * 80)
        for result in by_status['failed']:
            print(f"  ✗ {result.alert_name} ({result.namespace})")
            if result.error:
                error_lines = result.error.split('\n')[:3]
                for line in error_lines:
                    if line.strip():
                        print(f"    {line.strip()}")
        print()
    
    # Print successful alerts with sync status
    if summary.successful > 0 and not dry_run:
        synced_count = sum(1 for r in by_status['success'] if r.sync_status == 'RemoteSynced')
        if synced_count < summary.successful:
            print("Alerts Pending Sync:")
            print("-" * 80)
            for result in by_status['success']:
                if result.sync_status != 'RemoteSynced':
                    print(f"  ⚠ {result.alert_name} ({result.namespace}): {result.sync_status or 'pending'}")
            print()
    
    # Print statistics by namespace
    by_namespace = defaultdict(lambda: {'total': 0, 'success': 0, 'failed': 0})
    for result in summary.results:
        by_namespace[result.namespace]['total'] += 1
        if result.status == 'success':
            by_namespace[result.namespace]['success'] += 1
        elif result.status == 'failed':
            by_namespace[result.namespace]['failed'] += 1
    
    if len(by_namespace) > 1:
        print("By Namespace:")
        print("-" * 80)
        for namespace in sorted(by_namespace.keys()):
            stats = by_namespace[namespace]
            print(f"  {namespace}: {stats['success']}/{stats['total']} successful, {stats['failed']} failed")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate and deploy Coralogix Alert CRDs from PrometheusRule CRDs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--input-dir',
        type=Path,
        default=None,
        help='Directory to search for PrometheusRule YAML files (default: repo root)'
    )
    
    parser.add_argument(
        '--prometheus-file',
        type=Path,
        default=None,
        help='Specific PrometheusRule file to process (overrides --input-dir)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('generated/alerts'),
        help='Directory to write generated Alert CRDs (default: generated/alerts)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Generate alerts but don\'t deploy them (only validate)'
    )
    
    parser.add_argument(
        '--namespace',
        type=str,
        default=None,
        help='Override namespace for all alerts (optional)'
    )
    
    parser.add_argument(
        '--continue-on-error',
        action='store_true',
        help='Continue deploying even if some alerts fail'
    )
    
    parser.add_argument(
        '--wait-timeout',
        type=int,
        default=60,
        help='Timeout in seconds to wait for alert sync (default: 60, set to 0 to skip waiting)'
    )
    
    args = parser.parse_args()
    
    # Run deployment
    summary = generate_and_deploy_alerts(
        input_dir=args.input_dir,
        prometheus_file=args.prometheus_file,
        output_dir=args.output_dir.resolve(),
        dry_run=args.dry_run,
        namespace_override=args.namespace,
        continue_on_error=args.continue_on_error,
        wait_timeout=args.wait_timeout,
    )
    
    # Exit with appropriate code
    if summary.failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()

