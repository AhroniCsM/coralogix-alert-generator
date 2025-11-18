#!/usr/bin/env python3
"""
Unit tests for gen_alerts.py
"""

import tempfile
import unittest
from pathlib import Path
import yaml
import sys

# Add parent directory to path to import gen_alerts
sys.path.insert(0, str(Path(__file__).parent.parent))

from gen_alerts import (
    convert_prometheus_template_to_tera,
    sanitize_name,
    truncate_label_value,
    get_priority,
    parse_duration,
    convert_rule_to_alert,
    generate_alerts_from_prometheus_rules,
    verify_generated_files,
)


class TestTemplateConversion(unittest.TestCase):
    """Test template conversion from Prometheus to Tera syntax."""
    
    def test_simple_label_replacement(self):
        """Test simple $labels replacement."""
        input_text = 'Env "{{ $labels.environment }}" - data import failure'
        expected = 'Env "{{ alert.groups[0].keyValues.environment }}" - data import failure'
        result = convert_prometheus_template_to_tera(input_text)
        self.assertEqual(result, expected)
    
    def test_multiple_labels(self):
        """Test multiple $labels in one string."""
        input_text = 'Pod {{ $labels.pod }} in namespace {{ $labels.namespace }} has high CPU'
        expected = 'Pod {{ alert.groups[0].keyValues.pod }} in namespace {{ alert.groups[0].keyValues.namespace }} has high CPU'
        result = convert_prometheus_template_to_tera(input_text)
        self.assertEqual(result, expected)
    
    def test_no_spaces_in_braces(self):
        """Test $labels without spaces in braces."""
        input_text = '{{$labels.host}} is down'
        expected = '{{alert.groups[0].keyValues.host}} is down'
        result = convert_prometheus_template_to_tera(input_text)
        self.assertEqual(result, expected)
    
    def test_empty_string(self):
        """Test empty string."""
        result = convert_prometheus_template_to_tera('')
        self.assertEqual(result, '')
    
    def test_no_labels(self):
        """Test string without $labels."""
        input_text = 'This is a plain string without any labels'
        result = convert_prometheus_template_to_tera(input_text)
        self.assertEqual(result, input_text)
    
    def test_complex_description(self):
        """Test complex description with multiple labels."""
        input_text = 'Schema migrations {{ $labels.branch_name }} is hanged {{ $labels.org }}'
        expected = 'Schema migrations {{ alert.groups[0].keyValues.branch_name }} is hanged {{ alert.groups[0].keyValues.org }}'
        result = convert_prometheus_template_to_tera(input_text)
        self.assertEqual(result, expected)


class TestSanitizeName(unittest.TestCase):
    """Test name sanitization."""
    
    def test_simple_name(self):
        """Test simple name."""
        self.assertEqual(sanitize_name('test-alert'), 'test-alert')
    
    def test_uppercase(self):
        """Test uppercase conversion."""
        self.assertEqual(sanitize_name('TEST-ALERT'), 'test-alert')
    
    def test_special_characters(self):
        """Test special character replacement."""
        self.assertEqual(sanitize_name('test_alert@123'), 'test-alert-123')
    
    def test_leading_numbers(self):
        """Test leading numbers removal."""
        self.assertEqual(sanitize_name('123test'), 'test')
    
    def test_empty_result(self):
        """Test empty result handling."""
        self.assertEqual(sanitize_name('123'), 'alert')


class TestPriorityMapping(unittest.TestCase):
    """Test priority mapping from severity."""
    
    def test_critical_to_p1(self):
        """Test critical severity."""
        labels = {'severity': 'critical'}
        self.assertEqual(get_priority(labels), 'p1')
    
    def test_error_to_p2(self):
        """Test error severity."""
        labels = {'severity': 'error'}
        self.assertEqual(get_priority(labels), 'p2')
    
    def test_warning_to_p3(self):
        """Test warning severity."""
        labels = {'severity': 'warning'}
        self.assertEqual(get_priority(labels), 'p3')
    
    def test_info_to_p4(self):
        """Test info severity."""
        labels = {'severity': 'info'}
        self.assertEqual(get_priority(labels), 'p4')
    
    def test_low_to_p5(self):
        """Test low severity."""
        labels = {'severity': 'low'}
        self.assertEqual(get_priority(labels), 'p5')
    
    def test_case_insensitive(self):
        """Test case insensitive severity."""
        labels = {'severity': 'CRITICAL'}
        self.assertEqual(get_priority(labels), 'p1')
    
    def test_default_priority(self):
        """Test default priority when severity not found."""
        labels = {'team': 'devops'}
        self.assertEqual(get_priority(labels), 'p4')
    
    def test_empty_labels(self):
        """Test empty labels."""
        self.assertEqual(get_priority({}), 'p4')


class TestRuleToAlertConversion(unittest.TestCase):
    """Test conversion of PrometheusRule alert rule to Alert CRD."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.prometheus_rule = {
            'apiVersion': 'monitoring.coreos.com/v1',
            'kind': 'PrometheusRule',
            'metadata': {
                'name': 'test-prometheus-rule',
                'namespace': 'default',
                'uid': 'test-uid-123',
                'labels': {
                    'app': 'prometheus_rules',
                },
            },
        }
        
        self.rule = {
            'alert': 'High CPU Usage',
            'expr': 'sum(rate(container_cpu_usage_seconds_total[5m])) > 0.8',
            'for': '10m',
            'labels': {
                'severity': 'warning',
                'team': 'devops',
            },
            'annotations': {
                'description': 'Pod {{ $labels.pod }} has high CPU usage',
                'summary': 'CPU usage is above 80%',
            },
        }
    
    def test_basic_conversion(self):
        """Test basic rule conversion."""
        alert_crd = convert_rule_to_alert(self.rule, self.prometheus_rule, 0)
        
        # Check metadata
        self.assertEqual(alert_crd['apiVersion'], 'coralogix.com/v1beta1')
        self.assertEqual(alert_crd['kind'], 'Alert')
        self.assertEqual(alert_crd['metadata']['name'], 'test-prometheus-rule-high-cpu-usage-0')
        self.assertEqual(alert_crd['metadata']['namespace'], 'default')
        
        # Check labels
        labels = alert_crd['metadata']['labels']
        self.assertEqual(labels['app'], 'prometheus_rules')
        self.assertEqual(labels['app.kubernetes.io/managed-by'], 'test-prometheus-rule')
        # routing.group should NOT be in metadata.labels
        self.assertNotIn('routing.group', labels)
        
        # Check that ownerReferences are NOT present (standalone alerts)
        # We don't include ownerReferences when generating standalone Alert CRDs
        self.assertNotIn('ownerReferences', alert_crd['metadata'])
        
        # Check spec
        spec = alert_crd['spec']
        self.assertEqual(spec['name'], 'High CPU Usage')
        self.assertEqual(spec['priority'], 'p3')
        self.assertEqual(spec['enabled'], True)
        
        # Check entityLabels - should include rule labels plus routing.group
        entity_labels = spec['entityLabels']
        self.assertEqual(entity_labels['severity'], 'warning')
        self.assertEqual(entity_labels['team'], 'devops')
        self.assertEqual(entity_labels['routing.group'], 'main')  # routing.group should be in entityLabels
        
        # Check description conversion
        self.assertIn('alert.groups[0].keyValues.pod', spec['description'])
        self.assertNotIn('$labels.pod', spec['description'])
        
        # Check alert type
        alert_type = spec['alertType']['metricThreshold']
        self.assertEqual(alert_type['metricFilter']['promql'], self.rule['expr'])
        self.assertEqual(alert_type['rules'][0]['condition']['ofTheLast']['dynamicDuration'], '10m')
        self.assertEqual(alert_type['rules'][0]['condition']['threshold'], '0')
        self.assertEqual(alert_type['rules'][0]['condition']['forOverPct'], 100)
        self.assertEqual(alert_type['rules'][0]['condition']['conditionType'], 'moreThan')
    
    def test_multiple_rules_same_name(self):
        """Test multiple rules with same name get different indices."""
        alert1 = convert_rule_to_alert(self.rule, self.prometheus_rule, 0)
        alert2 = convert_rule_to_alert(self.rule, self.prometheus_rule, 1)
        
        self.assertEqual(alert1['metadata']['name'], 'test-prometheus-rule-high-cpu-usage-0')
        self.assertEqual(alert2['metadata']['name'], 'test-prometheus-rule-high-cpu-usage-1')
    
    def test_no_duration(self):
        """Test rule without 'for' field."""
        rule_no_duration = self.rule.copy()
        del rule_no_duration['for']
        
        alert_crd = convert_rule_to_alert(rule_no_duration, self.prometheus_rule, 0)
        duration = alert_crd['spec']['alertType']['metricThreshold']['rules'][0]['condition']['ofTheLast']['dynamicDuration']
        self.assertEqual(duration, '1m')  # Default


class TestGenerateAlerts(unittest.TestCase):
    """Test alert generation from PrometheusRules."""
    
    def test_single_prometheus_rule(self):
        """Test generating alerts from a single PrometheusRule."""
        prometheus_rules = [
            {
                'apiVersion': 'monitoring.coreos.com/v1',
                'kind': 'PrometheusRule',
                'metadata': {
                    'name': 'test-rule',
                    'namespace': 'default',
                    'uid': 'test-uid',
                    'labels': {},
                },
                'spec': {
                    'groups': [
                        {
                            'name': 'test_group',
                            'rules': [
                                {
                                    'alert': 'Test Alert',
                                    'expr': 'vector(1) > 0',
                                    'for': '5m',
                                    'labels': {'severity': 'critical'},
                                    'annotations': {'description': 'Test description'},
                                }
                            ],
                        }
                    ],
                },
            }
        ]
        
        alerts = generate_alerts_from_prometheus_rules(prometheus_rules)
        
        self.assertEqual(len(alerts), 1)
        alert_name, alert_crd = alerts[0]
        self.assertEqual(alert_name, 'test-rule-test-alert-0')
        self.assertEqual(alert_crd['spec']['name'], 'Test Alert')
    
    def test_multiple_alerts_same_name(self):
        """Test multiple alerts with same name."""
        prometheus_rules = [
            {
                'apiVersion': 'monitoring.coreos.com/v1',
                'kind': 'PrometheusRule',
                'metadata': {
                    'name': 'test-rule',
                    'namespace': 'default',
                    'uid': 'test-uid',
                    'labels': {},
                },
                'spec': {
                    'groups': [
                        {
                            'name': 'test_group',
                            'rules': [
                                {
                                    'alert': 'Test Alert',
                                    'expr': 'vector(1) > 0',
                                    'labels': {'severity': 'critical'},
                                },
                                {
                                    'alert': 'Test Alert',
                                    'expr': 'vector(2) > 0',
                                    'labels': {'severity': 'warning'},
                                },
                            ],
                        }
                    ],
                },
            }
        ]
        
        alerts = generate_alerts_from_prometheus_rules(prometheus_rules)
        
        self.assertEqual(len(alerts), 2)
        names = [name for name, _ in alerts]
        self.assertIn('test-rule-test-alert-0', names)
        self.assertIn('test-rule-test-alert-1', names)


class TestVerifyMode(unittest.TestCase):
    """Test verify mode functionality."""
    
    def test_verify_matching_files(self):
        """Test verify mode with matching files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            output_dir = temp_path / 'output'
            output_dir.mkdir()
            
            # Create a test alert
            alert_crd = {
                'apiVersion': 'coralogix.com/v1beta1',
                'kind': 'Alert',
                'metadata': {'name': 'test-alert'},
                'spec': {'name': 'Test Alert'},
            }
            
            # Write initial file
            alert_file = output_dir / 'test-alert-0.yaml'
            with open(alert_file, 'w') as f:
                yaml.dump(alert_crd, f, sort_keys=True)
            
            # Verify with same content
            alerts = [('test-alert-0', alert_crd)]
            success, messages = verify_generated_files(alerts, output_dir, [])
            
            self.assertTrue(success)
            self.assertIn('up-to-date', messages[-1])
    
    def test_verify_different_content(self):
        """Test verify mode with different content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            output_dir = temp_path / 'output'
            output_dir.mkdir()
            
            # Create existing file with different content
            existing_alert = {
                'apiVersion': 'coralogix.com/v1beta1',
                'kind': 'Alert',
                'metadata': {'name': 'test-alert'},
                'spec': {'name': 'Old Name'},
            }
            
            alert_file = output_dir / 'test-alert-0.yaml'
            with open(alert_file, 'w') as f:
                yaml.dump(existing_alert, f, sort_keys=True)
            
            # Verify with new content
            new_alert = {
                'apiVersion': 'coralogix.com/v1beta1',
                'kind': 'Alert',
                'metadata': {'name': 'test-alert'},
                'spec': {'name': 'New Name'},
            }
            
            alerts = [('test-alert-0', new_alert)]
            success, messages = verify_generated_files(alerts, output_dir, [])
            
            self.assertFalse(success)
            self.assertTrue(any('differs' in msg for msg in messages))


if __name__ == '__main__':
    unittest.main()

