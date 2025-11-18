#!/usr/bin/env python3
"""
PrometheusRule to Coralogix Alert CRD Generator

This script scans PrometheusRule CRD YAML files and generates corresponding
Coralogix Alert CRD YAML files. It converts Prometheus template syntax
($labels.*) to Tera template syntax (alert.groups[0].keyValues.*).

Usage:
    python scripts/gen_alerts.py [--input-dir DIR] [--output-dir DIR] [--verify]

Options:
    --input-dir DIR    Directory to search for PrometheusRule YAML files (default: repo root)
    --output-dir DIR   Directory to write generated Alert CRDs (default: generated/alerts)
    --verify           Verify mode: check if generated files are up-to-date (for CI)
"""

import argparse
import os
import re
import sys
import tempfile
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict


# Severity to priority mapping (from prometheusrule_controller.go)
SEVERITY_TO_PRIORITY = {
    "critical": "p1",
    "error": "p2",
    "warning": "p3",
    "info": "p4",
    "low": "p5",
}

# Default priority if severity is not found
DEFAULT_PRIORITY = "p4"

# Label keys used by the operator
MANAGED_BY_LABEL_KEY = "app.kubernetes.io/managed-by"
TRACK_ALERTS_LABEL_KEY = "app.coralogix.com/track-alerting-rules"
ROUTING_GROUP_LABEL_KEY = "routing.group"
ROUTING_GROUP_VALUE = "main"


def convert_prometheus_template_to_tera(text: str) -> str:
    """
    Convert Prometheus-style template expressions to Tera template expressions.
    
    Converts:
        {{ $labels.<name> }} → {{ alert.groups[0].keyValues.<name> }}
        {{$labels.<name>}} → {{alert.groups[0].keyValues.<name>}}
        $labels.<name> (within complex expressions) → alert.groups[0].keyValues.<name>
        printf functions → Tera-compatible format
        $value → alert.value (if in Tera context)
        Non-Tera expressions → generic replacement or removal
    
    Args:
        text: Input string with Prometheus template syntax
        
    Returns:
        String with Tera template syntax (Tera-only compatible)
    """
    if not text:
        return text
    
    result = text
    
    # First, handle Prometheus-specific functions that don't work in Tera
    # Replace printf "%.2f" $value with Tera format
    # Pattern: printf "format" $value (may be inside {{ }} or standalone)
    # We need to handle both cases: {{ printf "%.2f" $value }} and just printf "%.2f" $value
    printf_pattern = re.compile(r'\{\{\s*printf\s+"([^"]+)"\s+\$value\s*\}\}|\{\{printf\s+"([^"]+)"\s+\$value\}\}|printf\s+"([^"]+)"\s+\$value')
    def replace_printf(match: re.Match) -> str:
        # Get format string from any of the capture groups
        format_str = match.group(1) or match.group(2) or match.group(3)
        # Check if the match already includes {{ }}
        full_match = match.group(0)
        in_braces = full_match.startswith('{{')
        
        # Convert to Tera format filter
        if '%.2f' in format_str or '%.1f' in format_str:
            tera_expr = 'alert.value | round(method="ceil", precision=2)'
        elif '%f' in format_str:
            tera_expr = 'alert.value | round(method="ceil", precision=2)'
        elif '%d' in format_str:
            tera_expr = 'alert.value | round(method="ceil", precision=0)'
        else:
            tera_expr = 'alert.value'
        
        # If already in braces, just replace the content; otherwise wrap it
        if in_braces:
            return f'{{{{ {tera_expr} }}}}'
        else:
            return f'{{{{ {tera_expr} }}}}'
    
    result = printf_pattern.sub(replace_printf, result)
    
    # Replace standalone $value (not in printf) with alert.value
    # But only if it's in a template context
    standalone_value_pattern = re.compile(r'\{\{\s*\$value\s*\}\}')
    result = standalone_value_pattern.sub('{{ alert.value }}', result)
    
    # Replace $value in expressions (be careful not to break existing Tera)
    value_in_expr_pattern = re.compile(r'\$value(?!\w)')  # $value not followed by word char
    # Only replace if not already converted and in a template-like context
    def replace_value(match: re.Match) -> str:
        start_pos = match.start()
        # Check if we're in a {{ }} block
        text_before = result[:start_pos]
        last_open = text_before.rfind('{{')
        if last_open != -1:
            text_after = result[start_pos:]
            next_close = text_after.find('}}')
            if next_close != -1:
                # We're in a template block, replace with alert.value
                return 'alert.value'
        return match.group(0)  # Not in template, leave as is
    
    matches = list(value_in_expr_pattern.finditer(result))
    for match in reversed(matches):
        if 'alert.value' not in result[max(0, match.start()-20):match.end()+20]:
            result = result[:match.start()] + replace_value(match) + result[match.end():]
    
    # Handle standalone {{ $labels.<name> }} patterns
    # Pattern to match {{ $labels.<name> }} or {{$labels.<name>}}
    # Handles various whitespace scenarios
    standalone_pattern = re.compile(r'\{\{\s*\$labels\.(\w+)\s*\}\}')
    
    def replace_standalone(match: re.Match) -> str:
        label_name = match.group(1)
        # Preserve whitespace style from original
        full_match = match.group(0)
        if full_match.startswith("{{ ") and full_match.endswith(" }}"):
            return f"{{{{ alert.groups[0].keyValues.{label_name} }}}}"
        elif full_match.startswith("{{") and full_match.endswith("}}"):
            return f"{{{{alert.groups[0].keyValues.{label_name}}}}}"
        else:
            # Default with spaces
            return f"{{{{ alert.groups[0].keyValues.{label_name} }}}}"
    
    result = standalone_pattern.sub(replace_standalone, result)
    
    # Then, handle $labels.<name> within complex expressions (not in {{ }})
    # This handles cases like: {{ if eq $labels.instance_type "EMR" }}
    # We need to be careful not to replace already-converted patterns
    complex_pattern = re.compile(r'\$labels\.(\w+)')
    
    # Replace $labels.<name> that appear outside of already-converted {{ }} blocks
    # We need to check if the match is within a {{ }} that we haven't converted yet
    def should_replace(match: re.Match) -> bool:
        start_pos = match.start()
        # Check if this $labels is within a {{ }} block that contains it
        # Look backwards for {{
        text_before = result[:start_pos]
        last_open = text_before.rfind('{{')
        if last_open == -1:
            return True  # Not in a {{ }} block, safe to replace
        
        # Look forwards for }}
        text_after = result[start_pos:]
        next_close = text_after.find('}}')
        if next_close == -1:
            return True  # No closing }}, safe to replace
        
        # Check if this {{ }} block was already converted
        block = result[last_open:start_pos + next_close + 2]
        if 'alert.groups[0].keyValues' in block:
            return False  # Already converted, don't replace
        return True  # Not converted yet, safe to replace
    
    # Apply complex pattern replacement
    matches = list(complex_pattern.finditer(result))
    # Replace from end to start to preserve positions
    for match in reversed(matches):
        if should_replace(match):
            label_name = match.group(1)
            result = result[:match.start()] + f"alert.groups[0].keyValues.{label_name}" + result[match.end():]
    
    # Handle edge case: malformed templates like { $labels.xxx }} (missing opening {)
    malformed_pattern = re.compile(r'\{ \$labels\.(\w+)\s*\}\}')
    result = malformed_pattern.sub(r'{{ alert.groups[0].keyValues.\1 }}', result)
    
    # Clean up non-Tera expressions that don't make sense
    # Replace patterns like *<< env >>* or << env >> with generic text
    non_tera_pattern = re.compile(r'\*?<<\s*(\w+)\s*>>\*?')
    result = non_tera_pattern.sub(r'[field not supported in Tera]', result)
    
    # Replace any remaining Prometheus-specific syntax that's not Tera-compatible
    # Look for patterns like {{ .* }} that contain Prometheus-only functions
    # This is a catch-all for anything we might have missed
    
    return result


def sanitize_description_for_tera(text: str) -> str:
    """
    Sanitize description to ensure it's Tera-compatible.
    
    Replaces or removes non-Tera expressions with generic placeholders.
    Removes $value references and adds conditional environment display.
    
    Args:
        text: Input description text
        
    Returns:
        Tera-compatible description string
    """
    if not text:
        return text
    
    result = convert_prometheus_template_to_tera(text)
    
    # Remove VALUE = {{ $value }} or similar patterns
    # Pattern: VALUE = {{ alert.value }} or VALUE = {{alert.value}} or similar variations
    # Track if we removed a VALUE line that had a period
    removed_value_with_period = False
    if re.search(r'VALUE\s*=\s*.*\.', result, re.IGNORECASE):
        removed_value_with_period = True
    
    result = re.sub(r'\s*VALUE\s*=\s*\{\{\s*alert\.value\s*\}\}\s*\.?\s*', '', result, flags=re.IGNORECASE)
    result = re.sub(r'\s*VALUE\s*=\s*\{\{alert\.value\}\}\s*\.?\s*', '', result, flags=re.IGNORECASE)
    # Also remove standalone $value references that might have been converted
    result = re.sub(r'\s*VALUE\s*=\s*\{\{\s*\$value\s*\}\}\s*\.?\s*', '', result, flags=re.IGNORECASE)
    
    # Remove lines that only contain VALUE = ... (with any whitespace)
    lines = result.split('\n')
    cleaned_lines = []
    for line in lines:
        # Skip lines that are just "VALUE = ..." or similar
        if re.match(r'^\s*VALUE\s*=\s*.*$', line, re.IGNORECASE):
            continue
        cleaned_lines.append(line)
    result = '\n'.join(cleaned_lines)
    
    # Add conditional environment display at the end if not already present
    # This ensures environment is shown when available, but doesn't break if it's not
    has_environment_conditional = '{% if alert.groups[0].keyValues.environment' in result
    
    if not has_environment_conditional:
        # Add conditional environment display at the end
        result = result.rstrip()
        # Don't add period - the conditional environment display doesn't need it
        # Add conditional environment display
        result += '{% if alert.groups[0].keyValues.environment is defined and alert.groups[0].keyValues.environment | default(value="") != "" %} ENV = {{ alert.groups[0].keyValues.environment }}{% endif %}'
    
    # Remove or replace any remaining problematic patterns
    # Multiple consecutive quotes (like *''value''*)
    result = re.sub(r"\*'+", "*", result)  # Remove multiple quotes after *
    result = re.sub(r"'+\*", "*", result)  # Remove multiple quotes before *
    
    # Clean up excessive whitespace/newlines in descriptions
    result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)  # Max 2 consecutive newlines
    result = re.sub(r'\s+', ' ', result)  # Normalize multiple spaces to single space
    result = result.strip()
    
    # If description is empty or only contains non-Tera placeholders, provide a default
    if not result or result == '[field not supported in Tera]':
        return 'Alert description (field conversion not supported)'
    
    return result


def sanitize_name(name: str) -> str:
    """
    Convert name to valid Kubernetes resource name.
    
    Based on the Go sanitizeName function:
    - Lowercase
    - Replace invalid characters with '-'
    - Remove leading numbers (Kubernetes names can't start with numbers)
    - Trim leading/trailing non-alphanumeric characters
    
    Args:
        name: Input name
        
    Returns:
        Sanitized name
    """
    name = name.lower()
    # Replace any invalid characters (anything not a-z, 0-9, '-', or '.') with '-'
    name = re.sub(r'[^a-z0-9.-]+', '-', name)
    # Remove leading numbers (Kubernetes resource names can't start with numbers)
    name = re.sub(r'^[0-9]+', '', name)
    # Trim leading/trailing non-alphanumeric characters
    name = name.strip('-.')
    return name or 'alert'


def truncate_label_value(value: str, max_length: int = 63) -> str:
    """
    Truncate label value to max_length (Kubernetes label value limit).
    
    Args:
        value: Label value to truncate
        max_length: Maximum length (default: 63)
        
    Returns:
        Truncated value
    """
    if len(value) <= max_length:
        return value
    return value[:max_length]


def get_priority(rule_labels: Dict[str, str]) -> str:
    """
    Get alert priority from rule labels based on severity.
    
    Args:
        rule_labels: Labels from the PrometheusRule alert rule
        
    Returns:
        Priority string (p1-p5)
    """
    severity = rule_labels.get("severity", "").lower()
    return SEVERITY_TO_PRIORITY.get(severity, DEFAULT_PRIORITY)


def parse_duration(duration: Optional[str]) -> str:
    """
    Parse and normalize duration string.
    
    Args:
        duration: Duration string (e.g., "1h", "5m", "30s")
        
    Returns:
        Normalized duration string (default: "1m")
    """
    if not duration:
        return "1m"
    # Return as-is if it's a valid duration format
    # The operator expects duration strings like "1m", "5m", "1h", etc.
    return duration


def find_prometheus_rules(input_dir: Path) -> List[Path]:
    """
    Find all YAML files that might contain PrometheusRule CRDs.
    
    Args:
        input_dir: Directory to search
        
    Returns:
        List of file paths
    """
    yaml_files = []
    for root, dirs, files in os.walk(input_dir):
        # Skip hidden directories and common build/output directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'vendor', 'generated']]
        
        for file in files:
            if file.endswith(('.yaml', '.yml')):
                yaml_files.append(Path(root) / file)
    
    return yaml_files


def parse_prometheus_rules(file_path: Path) -> List[Dict[str, Any]]:
    """
    Parse a YAML file and extract PrometheusRule CRDs.
    
    Args:
        file_path: Path to YAML file
        
    Returns:
        List of PrometheusRule dictionaries
    """
    prometheus_rules = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Handle both single documents and multi-document YAML
            documents = list(yaml.safe_load_all(f))
            
            for doc in documents:
                if not doc:
                    continue
                
                # Check if this is a PrometheusRule CRD
                if (doc.get('apiVersion') == 'monitoring.coreos.com/v1' and
                    doc.get('kind') == 'PrometheusRule'):
                    prometheus_rules.append(doc)
                
                # Also handle List kind with items
                elif doc.get('kind') == 'List' and 'items' in doc:
                    for item in doc.get('items', []):
                        if (item.get('apiVersion') == 'monitoring.coreos.com/v1' and
                            item.get('kind') == 'PrometheusRule'):
                            prometheus_rules.append(item)
    
    except yaml.YAMLError as e:
        print(f"Warning: Failed to parse {file_path}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Error reading {file_path}: {e}", file=sys.stderr)
    
    return prometheus_rules


def convert_rule_to_alert(
    rule: Dict[str, Any],
    prometheus_rule: Dict[str, Any],
    index: int
) -> Dict[str, Any]:
    """
    Convert a PrometheusRule alert rule to a Coralogix Alert CRD.
    
    Args:
        rule: Alert rule from PrometheusRule spec.groups[].rules[]
        prometheus_rule: Full PrometheusRule CRD
        index: Index of this rule (for naming when multiple rules have same name)
        
    Returns:
        Coralogix Alert CRD dictionary
    """
    alert_name = rule.get('alert', '')
    if not alert_name:
        raise ValueError("Rule missing 'alert' field")
    
    # Generate Alert CRD name: <promRuleName>-<alertName>-<index>
    prom_rule_name = prometheus_rule['metadata']['name']
    sanitized_alert_name = sanitize_name(alert_name)
    alert_crd_name = f"{prom_rule_name}-{sanitized_alert_name}-{index}"
    
    # Get namespace from PrometheusRule or use default
    namespace = prometheus_rule['metadata'].get('namespace', 'default')
    
    # Get labels from PrometheusRule metadata
    labels = dict(prometheus_rule['metadata'].get('labels', {}))
    
    # Add required labels (but NOT routing.group - that goes in entityLabels)
    labels[MANAGED_BY_LABEL_KEY] = truncate_label_value(prom_rule_name)
    
    # Get rule labels and annotations
    rule_labels = rule.get('labels', {})
    rule_annotations = rule.get('annotations', {})
    
    # Convert description from Prometheus to Tera syntax
    # Use sanitize_description_for_tera to ensure Tera-only compatibility
    description = rule_annotations.get('description', '')
    description = sanitize_description_for_tera(description)
    
    # Convert template strings in entityLabels from Prometheus to Tera syntax
    # Start with rule labels, then add routing.group
    entity_labels = {}
    for key, value in rule_labels.items():
        if isinstance(value, str):
            # Convert any Prometheus/Go template syntax to Tera
            converted_value = convert_prometheus_template_to_tera(value)
            # If conversion resulted in something that's clearly not Tera-compatible,
            # use a generic placeholder
            # Check if it has template syntax but not Tera-compatible
            if '{{' in converted_value:
                # If it has template syntax, it must contain Tera-compatible expressions
                if 'alert.groups[0].keyValues' not in converted_value and 'alert.value' not in converted_value:
                    # Has template syntax but not Tera - replace with placeholder
                    converted_value = '[field conversion not supported]'
            entity_labels[key] = converted_value
        else:
            entity_labels[key] = value
    
    # Add routing.group to entityLabels (required)
    entity_labels[ROUTING_GROUP_LABEL_KEY] = ROUTING_GROUP_VALUE
    
    # Get priority from severity
    priority = get_priority(rule_labels)
    
    # Get duration (for field)
    duration = parse_duration(rule.get('for'))
    
    # Get PromQL expression
    expr = rule.get('expr', '')
    if isinstance(expr, dict):
        # Handle cases where expr might be a dict with StrVal
        expr = expr.get('StrVal', str(expr))
    expr = str(expr)
    
    # Build Alert CRD
    # Note: We don't include ownerReferences when generating standalone Alert CRDs
    # that can be deployed directly without PrometheusRule dependencies
    alert_crd = {
        'apiVersion': 'coralogix.com/v1beta1',
        'kind': 'Alert',
        'metadata': {
            'name': alert_crd_name,
            'namespace': namespace,
            'labels': labels,
            # No ownerReferences - these alerts are standalone and can be deployed directly
        },
        'spec': {
            'name': alert_name,
            'description': description,
            'priority': priority,
            'enabled': True,
            'entityLabels': entity_labels,
            'phantomMode': False,
            'alertType': {
                'metricThreshold': {
                    'metricFilter': {
                        'promql': expr,
                    },
                    'rules': [
                        {
                            'condition': {
                                'threshold': '0',
                                'forOverPct': 100,
                                'ofTheLast': {
                                    'dynamicDuration': duration,
                                },
                                'conditionType': 'moreThan',
                            },
                            'override': {
                                'priority': priority,
                            },
                        }
                    ],
                    'missingValues': {
                        'minNonNullValuesPct': 0,
                    },
                },
            },
        },
    }
    
    return alert_crd


def generate_alerts_from_prometheus_rules(
    prometheus_rules: List[Dict[str, Any]]
) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Generate Alert CRDs from a list of PrometheusRule CRDs.
    
    Args:
        prometheus_rules: List of PrometheusRule CRD dictionaries
        
    Returns:
        List of tuples: (alert_crd_name, alert_crd_dict)
    """
    alerts = []
    
    for prom_rule in prometheus_rules:
        # Group rules by alert name (lowercase) to handle duplicates
        alert_map = defaultdict(list)
        
        spec = prom_rule.get('spec', {})
        groups = spec.get('groups', [])
        
        for group in groups:
            rules = group.get('rules', [])
            for rule in rules:
                if 'alert' in rule:
                    alert_name_lower = rule['alert'].lower()
                    alert_map[alert_name_lower].append(rule)
        
        # Generate Alert CRD for each rule
        for alert_name_lower, rules in alert_map.items():
            for index, rule in enumerate(rules):
                try:
                    alert_crd = convert_rule_to_alert(rule, prom_rule, index)
                    alert_crd_name = alert_crd['metadata']['name']
                    alerts.append((alert_crd_name, alert_crd))
                except Exception as e:
                    print(f"Error converting rule '{rule.get('alert', 'unknown')}': {e}", file=sys.stderr)
                    continue
    
    return alerts


def write_alert_yaml(alert_crd: Dict[str, Any], output_path: Path) -> None:
    """
    Write Alert CRD to YAML file with atomic write.
    
    Args:
        alert_crd: Alert CRD dictionary
        output_path: Path to write the YAML file
    """
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temporary file first (atomic write)
    temp_path = output_path.with_suffix('.yaml.tmp')
    
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            yaml.dump(
                alert_crd,
                f,
                default_flow_style=False,
                sort_keys=True,
                allow_unicode=True,
                width=1000,  # Prevent line wrapping
            )
        
        # Atomic rename
        temp_path.replace(output_path)
    except Exception as e:
        # Clean up temp file on error
        if temp_path.exists():
            temp_path.unlink()
        raise e


def generate_alerts(
    input_dir: Path,
    output_dir: Path,
    verify: bool = False
) -> Tuple[bool, List[str]]:
    """
    Main generation function.
    
    Args:
        input_dir: Directory to search for PrometheusRule files
        output_dir: Directory to write generated Alert CRDs
        verify: If True, verify mode (check if files are up-to-date)
        
    Returns:
        Tuple of (success: bool, messages: List[str])
    """
    messages = []
    
    # Find all PrometheusRule files
    yaml_files = find_prometheus_rules(input_dir)
    messages.append(f"Found {len(yaml_files)} YAML files to scan")
    
    # Parse all PrometheusRule CRDs
    all_prometheus_rules = []
    for yaml_file in yaml_files:
        prometheus_rules = parse_prometheus_rules(yaml_file)
        all_prometheus_rules.extend(prometheus_rules)
    
    messages.append(f"Found {len(all_prometheus_rules)} PrometheusRule CRDs")
    
    # Generate Alert CRDs
    alerts = generate_alerts_from_prometheus_rules(all_prometheus_rules)
    messages.append(f"Generated {len(alerts)} Alert CRDs")
    
    if verify:
        # Verify mode: compare generated content with existing files
        return verify_generated_files(alerts, output_dir, messages)
    else:
        # Normal mode: write generated files
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for alert_name, alert_crd in alerts:
            output_path = output_dir / f"{alert_name}.yaml"
            write_alert_yaml(alert_crd, output_path)
        
        messages.append(f"Written {len(alerts)} Alert CRDs to {output_dir}")
        return True, messages


def verify_generated_files(
    alerts: List[Tuple[str, Dict[str, Any]]],
    output_dir: Path,
    messages: List[str]
) -> Tuple[bool, List[str]]:
    """
    Verify that generated files match existing files.
    
    Args:
        alerts: List of (alert_name, alert_crd_dict) tuples
        output_dir: Directory containing existing Alert CRDs
        messages: List of messages to append to
        
    Returns:
        Tuple of (success: bool, messages: List[str])
    """
    # Generate files to temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Write generated files to temp directory
        for alert_name, alert_crd in alerts:
            output_path = temp_path / f"{alert_name}.yaml"
            write_alert_yaml(alert_crd, output_path)
        
        # Compare with existing files
        existing_files = set()
        if output_dir.exists():
            existing_files = {f.name for f in output_dir.glob("*.yaml")}
        
        generated_files = {f"{alert_name}.yaml" for alert_name, _ in alerts}
        
        # Check for missing files
        missing = existing_files - generated_files
        if missing:
            messages.append(f"ERROR: {len(missing)} files should be removed: {', '.join(sorted(missing))}")
            return False, messages
        
        # Check for new files
        new_files = generated_files - existing_files
        if new_files:
            messages.append(f"ERROR: {len(new_files)} new files should be added: {', '.join(sorted(new_files))}")
            return False, messages
        
        # Compare file contents
        differences = []
        for alert_name, _ in alerts:
            generated_path = temp_path / f"{alert_name}.yaml"
            existing_path = output_dir / f"{alert_name}.yaml"
            
            if not existing_path.exists():
                differences.append(f"Missing file: {alert_name}.yaml")
                continue
            
            # Read and compare content
            with open(generated_path, 'r', encoding='utf-8') as f:
                generated_content = f.read()
            
            with open(existing_path, 'r', encoding='utf-8') as f:
                existing_content = f.read()
            
            if generated_content != existing_content:
                differences.append(f"Content differs: {alert_name}.yaml")
        
        if differences:
            messages.append(f"ERROR: {len(differences)} files have differences:")
            messages.extend(f"  - {diff}" for diff in differences[:10])
            if len(differences) > 10:
                messages.append(f"  ... and {len(differences) - 10} more")
            return False, messages
    
    messages.append("All generated files are up-to-date")
    return True, messages


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate Coralogix Alert CRDs from PrometheusRule CRDs',
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
        '--output-dir',
        type=Path,
        default=Path('generated/alerts'),
        help='Directory to write generated Alert CRDs (default: generated/alerts)'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify mode: check if generated files are up-to-date (for CI)'
    )
    
    args = parser.parse_args()
    
    # Determine input directory
    if args.input_dir:
        input_dir = args.input_dir.resolve()
    else:
        # Default to repo root (parent of scripts directory)
        script_dir = Path(__file__).parent.resolve()
        input_dir = script_dir.parent.resolve()
    
    if not input_dir.exists():
        print(f"Error: Input directory does not exist: {input_dir}", file=sys.stderr)
        sys.exit(1)
    
    # Run generation
    success, messages = generate_alerts(
        input_dir=input_dir,
        output_dir=args.output_dir.resolve(),
        verify=args.verify
    )
    
    # Print messages
    for message in messages:
        print(message)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

