#!/usr/bin/env python3
"""
Générateur de rapport HTML pour l'analyse de sécurité SAST et SCA
"""

import json
import os
from datetime import datetime
from pathlib import Path

def load_json_file(filepath, default=None):
    """Charge un fichier JSON avec gestion d'erreur"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️ Erreur lors du chargement de {filepath}: {e}")
        return default if default is not None else {}

def count_vulnerabilities_by_severity(npm_audit_data):
    """Compte les vulnérabilités par sévérité depuis npm audit"""
    severity_counts = {
        'critical': 0,
        'high': 0,
        'moderate': 0,
        'low': 0,
        'info': 0
    }
    
    if 'vulnerabilities' in npm_audit_data:
        for vuln_name, vuln_data in npm_audit_data['vulnerabilities'].items():
            severity = vuln_data.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    return severity_counts

def count_eslint_issues_by_severity(eslint_data):
    """Compte les problèmes ESLint par sévérité"""
    severity_counts = {
        'error': 0,
        'warning': 0
    }
    
    if isinstance(eslint_data, list):
        for file_result in eslint_data:
            if 'messages' in file_result:
                for message in file_result['messages']:
                    severity = 'error' if message.get('severity') == 2 else 'warning'
                    severity_counts[severity] += 1
    
    return severity_counts

def generate_html_report(reports_dir='./reports'):
    """Génère un rapport HTML complet"""
    
    # Charger les données
    npm_audit = load_json_file(f'{reports_dir}/sast/audit-report.json')
    eslint = load_json_file(f'{reports_dir}/sast/eslint-report.json', [])
    sca = load_json_file(f'{reports_dir}/sca/sca-report.json')
    
    # Analyser les données
    npm_severity = count_vulnerabilities_by_severity(npm_audit)
    sca_severity = count_vulnerabilities_by_severity(sca)
    eslint_severity = count_eslint_issues_by_severity(eslint)
    
    # Calculer les totaux
    total_npm_vulns = sum(npm_severity.values())
    total_sca_vulns = sum(sca_severity.values())
    total_eslint_issues = sum(eslint_severity.values())
    
    # Générer le HTML
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - SAST & SCA</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .header .timestamp {{
            margin-top: 15px;
            font-size: 0.9em;
            opacity: 0.8;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }}
        
        .card {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            border-left: 5px solid #667eea;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }}
        
        .card h2 {{
            color: #667eea;
            font-size: 1.3em;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .card-icon {{
            font-size: 1.5em;
        }}
        
        .card-stats {{
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}
        
        .stat-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 0.95em;
        }}
        
        .stat-label {{
            font-weight: 500;
            color: #495057;
        }}
        
        .stat-value {{
            font-weight: bold;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        
        .severity-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .severity-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity-moderate {{
            background: #ffc107;
            color: #000;
        }}
        
        .severity-low {{
            background: #20c997;
            color: white;
        }}
        
        .severity-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .severity-error {{
            background: #dc3545;
            color: white;
        }}
        
        .severity-warning {{
            background: #ffc107;
            color: #000;
        }}
        
        .total-badge {{
            background: #667eea;
            color: white;
            padding: 8px 16px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .section {{
            margin: 40px 0;
        }}
        
        .section-title {{
            font-size: 1.8em;
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .vulnerability-list {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
        }}
        
        .vuln-item {{
            background: white;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .vuln-name {{
            font-weight: bold;
            color: #2d3748;
            font-size: 1.1em;
        }}
        
        .vuln-details {{
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .eslint-file {{
            background: white;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid #ffc107;
        }}
        
        .eslint-filename {{
            font-weight: bold;
            color: #2d3748;
            margin-bottom: 10px;
            font-family: 'Courier New', monospace;
        }}
        
        .eslint-message {{
            padding: 8px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin: 20px 0;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }}
        
        .chart-title {{
            text-align: center;
            font-size: 1.3em;
            color: #2d3748;
            margin-bottom: 20px;
        }}
        
        .bar-chart {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        
        .bar-item {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .bar-label {{
            min-width: 120px;
            font-weight: 500;
            text-transform: capitalize;
        }}
        
        .bar-container {{
            flex: 1;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            height: 30px;
            position: relative;
        }}
        
        .bar-fill {{
            height: 100%;
            border-radius: 10px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }}
        
        .no-issues {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
        }}
        
        .no-issues::before {{
            content: "✅";
            display: block;
            font-size: 3em;
            margin-bottom: 10px;
        }}
        
        @media (max-width: 768px) {{
            .summary-cards {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .content {{
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Analysis Report</h1>
            <div class="subtitle">SAST & SCA Analysis Results</div>
            <div class="timestamp">Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S UTC')}</div>
        </div>
        
        <div class="content">
            <!-- Summary Cards -->
            <div class="summary-cards">
                <div class="card">
                    <h2><span class="card-icon">🔍</span>SAST - NPM Audit</h2>
                    <div class="card-stats">
                        <div class="stat-item">
                            <span class="stat-label">Total Vulnerabilities</span>
                            <span class="total-badge">{total_npm_vulns}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Critical</span>
                            <span class="stat-value severity-critical">{npm_severity['critical']}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">High</span>
                            <span class="stat-value severity-high">{npm_severity['high']}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Moderate</span>
                            <span class="stat-value severity-moderate">{npm_severity['moderate']}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Low</span>
                            <span class="stat-value severity-low">{npm_severity['low']}</span>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <h2><span class="card-icon">📋</span>SAST - ESLint</h2>
                    <div class="card-stats">
                        <div class="stat-item">
                            <span class="stat-label">Total Issues</span>
                            <span class="total-badge">{total_eslint_issues}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Errors</span>
                            <span class="stat-value severity-error">{eslint_severity['error']}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Warnings</span>
                            <span class="stat-value severity-warning">{eslint_severity['warning']}</span>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <h2><span class="card-icon">📦</span>SCA - Dependencies</h2>
                    <div class="card-stats">
                        <div class="stat-item">
                            <span class="stat-label">Total Vulnerabilities</span>
                            <span class="total-badge">{total_sca_vulns}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Critical</span>
                            <span class="stat-value severity-critical">{sca_severity['critical']}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">High</span>
                            <span class="stat-value severity-high">{sca_severity['high']}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Moderate</span>
                            <span class="stat-value severity-moderate">{sca_severity['moderate']}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Low</span>
                            <span class="stat-value severity-low">{sca_severity['low']}</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Charts -->
            <div class="chart-container">
                <div class="chart-title">Vulnerability Distribution (NPM Audit)</div>
                <div class="bar-chart">
"""
    
    # Générer les barres pour NPM Audit
    max_npm = max(npm_severity.values()) if max(npm_severity.values()) > 0 else 1
    for severity, count in npm_severity.items():
        if count > 0:
            width = (count / max_npm) * 100
            color_class = f"severity-{severity}"
            html_content += f"""
                    <div class="bar-item">
                        <div class="bar-label">{severity.capitalize()}</div>
                        <div class="bar-container">
                            <div class="bar-fill {color_class}" style="width: {width}%">{count}</div>
                        </div>
                    </div>
"""
    
    html_content += """
                </div>
            </div>
            
            <!-- Detailed Vulnerabilities -->
"""
    
    # Section NPM Audit Détails
    if total_npm_vulns > 0:
        html_content += """
            <div class="section">
                <h2 class="section-title">🔍 SAST - NPM Audit Details</h2>
                <div class="vulnerability-list">
"""
        if 'vulnerabilities' in npm_audit:
            for vuln_name, vuln_data in list(npm_audit['vulnerabilities'].items())[:20]:  # Limiter à 20
                severity = vuln_data.get('severity', 'info')
                via = vuln_data.get('via', [])
                fix_available = vuln_data.get('fixAvailable', False)
                
                html_content += f"""
                    <div class="vuln-item">
                        <div class="vuln-header">
                            <div class="vuln-name">{vuln_name}</div>
                            <span class="stat-value severity-{severity.lower()}">{severity}</span>
                        </div>
                        <div class="vuln-details">
                            <div><strong>Fix Available:</strong> {'Yes ✅' if fix_available else 'No ❌'}</div>
                            {f'<div><strong>Via:</strong> {", ".join([str(v) for v in via[:3]])}</div>' if via else ''}
                        </div>
                    </div>
"""
        
        html_content += """
                </div>
            </div>
"""
    else:
        html_content += """
            <div class="section">
                <h2 class="section-title">🔍 SAST - NPM Audit Details</h2>
                <div class="no-issues">No vulnerabilities found in NPM Audit</div>
            </div>
"""
    
    # Section ESLint Détails
    if total_eslint_issues > 0:
        html_content += """
            <div class="section">
                <h2 class="section-title">📋 SAST - ESLint Issues</h2>
                <div class="vulnerability-list">
"""
        files_with_issues = [f for f in eslint if f.get('messages')]
        for file_data in files_with_issues[:10]:  # Limiter à 10 fichiers
            filepath = file_data.get('filePath', 'Unknown')
            messages = file_data.get('messages', [])
            
            html_content += f"""
                    <div class="eslint-file">
                        <div class="eslint-filename">📄 {filepath}</div>
"""
            for msg in messages[:5]:  # Limiter à 5 messages par fichier
                severity_class = 'severity-error' if msg.get('severity') == 2 else 'severity-warning'
                severity_text = 'Error' if msg.get('severity') == 2 else 'Warning'
                html_content += f"""
                        <div class="eslint-message">
                            <span class="stat-value {severity_class}">{severity_text}</span>
                            Line {msg.get('line', '?')}:{msg.get('column', '?')} - {msg.get('message', 'No message')}
                            {f'<br><small>Rule: {msg.get("ruleId", "unknown")}</small>' if msg.get('ruleId') else ''}
                        </div>
"""
            html_content += """
                    </div>
"""
        
        html_content += """
                </div>
            </div>
"""
    else:
        html_content += """
            <div class="section">
                <h2 class="section-title">📋 SAST - ESLint Issues</h2>
                <div class="no-issues">No ESLint issues found</div>
            </div>
"""
    
    # Section SCA Détails
    if total_sca_vulns > 0:
        html_content += """
            <div class="section">
                <h2 class="section-title">📦 SCA - Dependency Vulnerabilities</h2>
                <div class="vulnerability-list">
"""
        if 'vulnerabilities' in sca:
            for vuln_name, vuln_data in list(sca['vulnerabilities'].items())[:20]:
                severity = vuln_data.get('severity', 'info')
                fix_available = vuln_data.get('fixAvailable', False)
                
                html_content += f"""
                    <div class="vuln-item">
                        <div class="vuln-header">
                            <div class="vuln-name">{vuln_name}</div>
                            <span class="stat-value severity-{severity.lower()}">{severity}</span>
                        </div>
                        <div class="vuln-details">
                            <div><strong>Fix Available:</strong> {'Yes ✅' if fix_available else 'No ❌'}</div>
                        </div>
                    </div>
"""
        
        html_content += """
                </div>
            </div>
"""
    else:
        html_content += """
            <div class="section">
                <h2 class="section-title">📦 SCA - Dependency Vulnerabilities</h2>
                <div class="no-issues">No dependency vulnerabilities found</div>
            </div>
"""
    
    html_content += """
        </div>
        
        <div class="footer">
            <p>Generated by Security Pipeline | Powered by GitHub Actions</p>
            <p>For more information, check the detailed JSON reports</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Sauvegarder le fichier HTML
    output_dir = Path(reports_dir) / 'global'
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / 'SECURITY_REPORT.html'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Rapport HTML généré avec succès: {output_file}")
    print(f"📊 Statistiques:")
    print(f"   - NPM Audit: {total_npm_vulns} vulnérabilités")
    print(f"   - ESLint: {total_eslint_issues} problèmes")
    print(f"   - SCA: {total_sca_vulns} vulnérabilités")
    
    return str(output_file)

if __name__ == "__main__":
    reports_dir = os.getenv('REPORTS_DIR', './reports')
    generate_html_report(reports_dir)