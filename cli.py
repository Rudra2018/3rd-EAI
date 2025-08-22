#!/usr/bin/env python3
import click
import json
import sys
from scanner.core import APISecurityScanner
from integrations.postman import PostmanIntegration
from ml.false_positive_detector import FalsePositiveDetector

@click.group()
@click.version_option(version='0.2.0')
def cli():
    """AI/ML-powered API Security Testing Tool"""
    pass

@cli.command()
@click.option('--url', required=True, help='Target URL to scan')
@click.option('--method', default='GET', help='HTTP method (GET, POST, etc.)')
@click.option('--output', default='scan-results.json', help='Output file')
@click.option('--format', 'output_format', default='json', type=click.Choice(['json', 'table']))
@click.option('--no-ml', is_flag=True, help='Disable ML false positive detection')
def scan_url(url, method, output, output_format, no_ml):
    """Scan a single URL"""
    click.echo(f"🔍 Scanning {method} {url}")
    
    scanner = APISecurityScanner()
    vulnerabilities = scanner.scan_endpoint(url, method)
    
    # Convert to dict format
    vuln_dicts = [vuln.to_dict() for vuln in vulnerabilities]
    
    # Add ML data if available
    for i, vuln in enumerate(vulnerabilities):
        if hasattr(vuln, 'false_positive_probability'):
            vuln_dicts[i]['false_positive_probability'] = vuln.false_positive_probability
            vuln_dicts[i]['ml_notes'] = vuln.ml_notes
    
    results = {
        'scan_info': {
            'target': url,
            'method': method,
            'ml_enabled': not no_ml
        },
        'summary': {
            'total': len(vuln_dicts),
            'critical': len([v for v in vuln_dicts if v['severity'] == 'Critical']),
            'high': len([v for v in vuln_dicts if v['severity'] == 'High']),
            'medium': len([v for v in vuln_dicts if v['severity'] == 'Medium']),
            'low': len([v for v in vuln_dicts if v['severity'] == 'Low'])
        },
        'vulnerabilities': vuln_dicts
    }
    
    if output_format == 'json':
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"📄 Results saved to {output}")
    else:
        # Table format
        click.echo("\n📊 Scan Results:")
        click.echo(f"Total vulnerabilities: {results['summary']['total']}")
        for vuln in vuln_dicts:
            fp_info = ""
            if 'false_positive_probability' in vuln:
                fp_info = f" (FP Risk: {vuln['false_positive_probability']:.1%})"
            click.echo(f"  • {vuln['type']} ({vuln['severity']}){fp_info}")

@cli.command()
@click.option('--collection', required=True, help='Path to Postman collection file')
@click.option('--output', default='postman-scan-results.json', help='Output file')
@click.option('--folders', help='Comma-separated list of folders to scan')
def scan_postman(collection, output, folders):
    """Scan a Postman collection"""
    click.echo(f"📦 Scanning Postman collection: {collection}")
    
    selected_folders = folders.split(',') if folders else None
    
    integration = PostmanIntegration()
    vulnerabilities = integration.run_security_scan(collection, selected_folders)
    
    report = integration.generate_security_report(vulnerabilities, output)
    
    click.echo(f"✅ Scan complete! Found {report['scan_summary']['total_vulnerabilities']} vulnerabilities")
    click.echo(f"📄 Report saved to {output}")

@cli.command()
@click.option('--retrain', is_flag=True, help='Force retrain the ML model')
def train_ml(retrain):
    """Train or retrain the ML false positive detection model"""
    click.echo("🤖 Training ML false positive detection model...")
    
    detector = FalsePositiveDetector()
    detector.train_model(force_retrain=retrain)
    
    click.echo("✅ ML model training complete!")

if __name__ == '__main__':
    cli()

