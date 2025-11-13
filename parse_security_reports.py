#!/usr/bin/env python3
"""
Advanced Security Reports Parser for LLM-based Policy Generation
Parses SAST, DAST, and SCA reports with detailed vulnerability extraction
Prepares data for NIST CSF and ISO 27001 policy generation
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict


@dataclass
class Vulnerability:
    """Structured vulnerability data"""
    id: str
    source: str  # SAST, DAST, SCA
    category: str
    severity: str
    title: str
    description: str
    affected_component: str
    cvss_score: Optional[float]
    cwe_ids: List[str]
    remediation: str
    references: List[str]
    is_direct_dependency: Optional[bool] = None
    exploit_available: Optional[bool] = None
    
    def to_dict(self):
        return asdict(self)


class AdvancedSecurityParser:
    """Advanced parser for security reports with LLM preparation"""
    
    def __init__(self, reports_dir: str = "./reports"):
        self.reports_dir = Path(reports_dir)
        self.vulnerabilities: List[Vulnerability] = []
        self.metrics = {}
        self.security_posture = {}
        
    def load_json_safe(self, file_path: Path) -> Dict:
        """Safely load JSON with error handling"""
        try:
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    print(f"  ✓ Loaded: {file_path.name}")
                    return data
            else:
                print(f"  ⚠️  Not found: {file_path}")
                return {}
        except json.JSONDecodeError as e:
            print(f"  ❌ JSON error in {file_path}: {e}")
            return {}
        except Exception as e:
            print(f"  ❌ Error reading {file_path}: {e}")
            return {}
    
    def parse_all(self) -> Dict[str, Any]:
        """Parse all security reports comprehensively"""
        print("=" * 80)
        print("🔐 Advanced Security Reports Parser")
        print("=" * 80)
        print()
        
        # Try global report first
        global_report = self.reports_dir / "global" / "global-report.json"
        
        if global_report.exists():
            print("📊 Loading consolidated global report...")
            data = self.load_json_safe(global_report)
            self.parse_from_global(data)
        else:
            print("📊 Loading individual reports...")
            self.parse_individual_reports()
        
        print("\n📈 Calculating security metrics...")
        self.calculate_comprehensive_metrics()
        
        print("🎯 Analyzing security posture...")
        self.analyze_security_posture()
        
        print("📋 Preparing LLM context...")
        llm_context = self.prepare_llm_context()
        
        print("\n✅ Parsing completed!")
        return {
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'metrics': self.metrics,
            'security_posture': self.security_posture,
            'llm_context': llm_context
        }
    
    def parse_from_global(self, data: Dict):
        """Parse from global consolidated report"""
        sast_data = data.get('sast', {})
        dast_data = data.get('dast', {})
        sca_data = data.get('sca', {})
        
        print("\n🔍 Parsing SAST results...")
        self.parse_sast_detailed(sast_data)
        
        print("\n🔍 Parsing DAST results...")
        self.parse_dast_detailed(dast_data)
        
        print("\n🔍 Parsing SCA results...")
        self.parse_sca_detailed(sca_data)
    
    def parse_individual_reports(self):
        """Parse individual report files"""
        # SAST
        npm_audit = self.load_json_safe(self.reports_dir / "sast" / "audit-report.json")
        eslint = self.load_json_safe(self.reports_dir / "sast" / "eslint-report.json")
        self.parse_sast_detailed({'npm_audit': npm_audit, 'eslint': eslint})
        
        # DAST
        dast = self.load_json_safe(self.reports_dir / "dast" / "report_json.json")
        self.parse_dast_detailed(dast)
        
        # SCA
        sca = self.load_json_safe(self.reports_dir / "sca" / "sca-report.json")
        self.parse_sca_detailed(sca)
    
    def parse_sast_detailed(self, sast_data: Dict):
        """Detailed SAST parsing with vulnerability extraction"""
        npm_audit = sast_data.get('npm_audit', {})
        
        if npm_audit.get('error'):
            print("  ⚠️  SAST data not available")
            return
        
        vulns = npm_audit.get('vulnerabilities', {})
        
        for pkg_name, vuln_info in vulns.items():
            severity = vuln_info.get('severity', 'unknown')
            is_direct = vuln_info.get('isDirect', False)
            
            # Process each vulnerability detail
            via_list = vuln_info.get('via', [])
            for via in via_list:
                if isinstance(via, dict):
                    vuln = Vulnerability(
                        id=f"SAST-{via.get('source', 'unknown')}",
                        source="SAST",
                        category=self._categorize_vulnerability(via.get('cwe', [])),
                        severity=severity,
                        title=via.get('title', f"Vulnerability in {pkg_name}"),
                        description=f"Package: {pkg_name}\n{via.get('title', '')}",
                        affected_component=pkg_name,
                        cvss_score=via.get('cvss', {}).get('score'),
                        cwe_ids=via.get('cwe', []),
                        remediation=self._generate_remediation(pkg_name, vuln_info),
                        references=[via.get('url', '')] if via.get('url') else [],
                        is_direct_dependency=is_direct,
                        exploit_available=None
                    )
                    self.vulnerabilities.append(vuln)
        
        print(f"  ✓ Extracted {len([v for v in self.vulnerabilities if v.source == 'SAST'])} SAST vulnerabilities")
    
    def parse_dast_detailed(self, dast_data: Dict):
        """Detailed DAST parsing with security finding extraction"""
        if dast_data.get('error') or dast_data.get('status') == 'failed':
            print("  ⚠️  DAST data not available")
            return
        
        sites = dast_data.get('site', [])
        if not isinstance(sites, list):
            sites = [sites] if sites else []
        
        for site in sites:
            site_url = site.get('@name', 'unknown')
            alerts = site.get('alerts', [])
            
            for alert in alerts:
                vuln = Vulnerability(
                    id=f"DAST-{alert.get('pluginid', 'unknown')}",
                    source="DAST",
                    category=self._map_dast_category(alert.get('pluginid', '')),
                    severity=self._map_risk_code(alert.get('riskcode', '0')),
                    title=alert.get('alert', 'Unknown Security Issue'),
                    description=alert.get('desc', ''),
                    affected_component=site_url,
                    cvss_score=None,
                    cwe_ids=[alert.get('cweid', '')] if alert.get('cweid') else [],
                    remediation=alert.get('solution', 'No solution provided'),
                    references=self._extract_references(alert.get('reference', '')),
                    is_direct_dependency=None,
                    exploit_available=None
                )
                self.vulnerabilities.append(vuln)
        
        print(f"  ✓ Extracted {len([v for v in self.vulnerabilities if v.source == 'DAST'])} DAST findings")
    
    def parse_sca_detailed(self, sca_data: Dict):
        """Detailed SCA parsing"""
        if sca_data.get('error'):
            print("  ⚠️  SCA data not available")
            return
        
        vulns = sca_data.get('vulnerabilities', {})
        
        for component, vuln_info in vulns.items():
            # Avoid duplicates with SAST
            if not any(v.affected_component == component and v.source == "SAST" 
                      for v in self.vulnerabilities):
                vuln = Vulnerability(
                    id=f"SCA-{component}",
                    source="SCA",
                    category="Supply Chain",
                    severity=vuln_info.get('severity', 'unknown'),
                    title=f"Vulnerable dependency: {component}",
                    description=f"Component {component} has known vulnerabilities",
                    affected_component=component,
                    cvss_score=None,
                    cwe_ids=[],
                    remediation=self._generate_remediation(component, vuln_info),
                    references=[],
                    is_direct_dependency=vuln_info.get('isDirect', False),
                    exploit_available=None
                )
                self.vulnerabilities.append(vuln)
        
        print(f"  ✓ Extracted {len([v for v in self.vulnerabilities if v.source == 'SCA'])} SCA vulnerabilities")
    
    def calculate_comprehensive_metrics(self):
        """Calculate detailed security metrics"""
        
        # Severity distribution
        severity_counts = defaultdict(int)
        for v in self.vulnerabilities:
            severity_counts[v.severity.lower()] += 1
        
        # Source distribution
        source_counts = defaultdict(int)
        for v in self.vulnerabilities:
            source_counts[v.source] += 1
        
        # Category distribution
        category_counts = defaultdict(int)
        for v in self.vulnerabilities:
            category_counts[v.category] += 1
        
        # CWE analysis
        cwe_counts = defaultdict(int)
        for v in self.vulnerabilities:
            for cwe in v.cwe_ids:
                if cwe:
                    cwe_counts[cwe] += 1
        
        # Direct vs Indirect dependencies
        direct_vulns = len([v for v in self.vulnerabilities if v.is_direct_dependency == True])
        indirect_vulns = len([v for v in self.vulnerabilities if v.is_direct_dependency == False])
        
        # Remediable vulnerabilities
        remediable = len([v for v in self.vulnerabilities 
                         if "update" in v.remediation.lower() or "upgrade" in v.remediation.lower()])
        
        self.metrics = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': {
                'critical': severity_counts.get('critical', 0),
                'high': severity_counts.get('high', 0),
                'medium': severity_counts.get('medium', 0) + severity_counts.get('moderate', 0),
                'low': severity_counts.get('low', 0),
                'informational': severity_counts.get('informational', 0)
            },
            'by_source': dict(source_counts),
            'by_category': dict(category_counts),
            'top_cwes': dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'dependency_breakdown': {
                'direct': direct_vulns,
                'indirect': indirect_vulns,
                'unknown': len(self.vulnerabilities) - direct_vulns - indirect_vulns
            },
            'remediable_count': remediable,
            'remediation_rate': round(remediable / len(self.vulnerabilities) * 100, 2) if self.vulnerabilities else 0
        }
    
    def analyze_security_posture(self):
        """Analyze overall security posture"""
        total = len(self.vulnerabilities)
        critical_high = self.metrics['by_severity']['critical'] + self.metrics['by_severity']['high']
        
        # Risk score (0-100, higher is worse)
        risk_score = min(100, (
            self.metrics['by_severity']['critical'] * 10 +
            self.metrics['by_severity']['high'] * 5 +
            self.metrics['by_severity']['medium'] * 2 +
            self.metrics['by_severity']['low'] * 1
        ))
        
        # Security maturity indicators
        has_dast = self.metrics['by_source'].get('DAST', 0) > 0
        has_sast = self.metrics['by_source'].get('SAST', 0) > 0
        has_sca = self.metrics['by_source'].get('SCA', 0) > 0
        
        # Compliance gaps
        compliance_gaps = []
        if critical_high > 0:
            compliance_gaps.append("Critical/High vulnerabilities present")
        if not has_dast:
            compliance_gaps.append("No runtime security testing")
        if self.metrics['dependency_breakdown']['direct'] > 5:
            compliance_gaps.append("Multiple vulnerable direct dependencies")
        
        self.security_posture = {
            'risk_score': risk_score,
            'risk_level': self._categorize_risk(risk_score),
            'critical_high_count': critical_high,
            'scan_coverage': {
                'sast': has_sast,
                'dast': has_dast,
                'sca': has_sca
            },
            'compliance_gaps': compliance_gaps,
            'recommended_actions': self._generate_recommendations(),
            'nist_csf_alignment': self._map_to_nist_csf(),
            'iso27001_alignment': self._map_to_iso27001()
        }
    
    def prepare_llm_context(self) -> Dict[str, Any]:
        """Prepare comprehensive context for LLM policy generation"""
        
        # Group vulnerabilities by category for policy generation
        vulns_by_category = defaultdict(list)
        for v in self.vulnerabilities:
            vulns_by_category[v.category].append(v.to_dict())
        
        # Extract key findings for policy focus
        critical_findings = [
            v.to_dict() for v in self.vulnerabilities 
            if v.severity.lower() in ['critical', 'high']
        ]
        
        # Compliance requirements based on findings
        compliance_requirements = self._extract_compliance_requirements()
        
        return {
            'vulnerabilities_by_category': dict(vulns_by_category),
            'critical_findings': critical_findings[:20],  # Top 20 for LLM context
            'metrics': self.metrics,
            'security_posture': self.security_posture,
            'compliance_requirements': compliance_requirements,
            'policy_generation_hints': {
                'focus_areas': list(vulns_by_category.keys()),
                'severity_priority': ['critical', 'high', 'medium', 'low'],
                'frameworks': ['NIST CSF 2.0', 'ISO 27001:2022'],
                'must_address': [
                    f for f in critical_findings 
                    if f['severity'].lower() in ['critical', 'high']
                ][:10]
            }
        }
    
    def _categorize_vulnerability(self, cwe_ids: List[str]) -> str:
        """Categorize vulnerability based on CWE"""
        cwe_categories = {
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-89': 'SQL Injection',
            'CWE-352': 'Cross-Site Request Forgery (CSRF)',
            'CWE-918': 'Server-Side Request Forgery (SSRF)',
            'CWE-770': 'Denial of Service',
            'CWE-1333': 'Regular Expression DoS',
            'CWE-693': 'Security Configuration',
            'CWE-1021': 'UI Security',
            'CWE-74': 'Injection',
            'CWE-144': 'Improper Input Validation',
            'CWE-346': 'Origin Validation Error',
            'CWE-749': 'Exposed Dangerous Method',
            'CWE-615': 'Information Exposure',
            'CWE-1395': 'Vulnerable Component'
        }
        
        for cwe in cwe_ids:
            if cwe in cwe_categories:
                return cwe_categories[cwe]
        
        return 'General Security Issue'
    
    def _map_dast_category(self, plugin_id: str) -> str:
        """Map DAST plugin ID to category"""
        categories = {
            '10003': 'Vulnerable Component',
            '10038': 'Security Headers',
            '10020': 'UI Security',
            '90004': 'Browser Security',
            '10063': 'Security Headers',
            '10021': 'Security Headers',
            '10027': 'Information Disclosure',
            '10109': 'Application Architecture'
        }
        return categories.get(plugin_id, 'General Security')
    
    def _generate_remediation(self, component: str, vuln_info: Dict) -> str:
        """Generate remediation advice"""
        fix = vuln_info.get('fixAvailable')
        if fix:
            return f"Update {component} to version {fix.get('version', 'latest')}"
        return f"Review and update {component} to address security vulnerabilities"
    
    def _extract_references(self, ref_text: str) -> List[str]:
        """Extract URLs from reference text"""
        if not ref_text:
            return []
        return [line.strip() for line in ref_text.split('\n') if line.strip().startswith('http')]
    
    def _map_risk_code(self, code: str) -> str:
        """Map ZAP risk code to severity"""
        risk_map = {
            '0': 'informational',
            '1': 'low',
            '2': 'medium',
            '3': 'high',
            '4': 'critical'
        }
        return risk_map.get(str(code), 'unknown')
    
    def _categorize_risk(self, score: int) -> str:
        """Categorize risk level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "MINIMAL"
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        critical_high = self.metrics['by_severity']['critical'] + self.metrics['by_severity']['high']
        if critical_high > 0:
            recommendations.append(f"URGENT: Address {critical_high} critical/high severity vulnerabilities immediately")
        
        if self.metrics['dependency_breakdown']['direct'] > 0:
            recommendations.append(f"Update {self.metrics['dependency_breakdown']['direct']} direct dependencies with known vulnerabilities")
        
        if not self.metrics['by_source'].get('DAST'):
            recommendations.append("Implement runtime security testing (DAST) to identify deployment-specific issues")
        
        if self.metrics['remediation_rate'] < 50:
            recommendations.append("Many vulnerabilities lack clear fixes - consider component alternatives")
        
        return recommendations
    
    def _map_to_nist_csf(self) -> Dict[str, List[str]]:
        """Map findings to NIST CSF 2.0 functions"""
        return {
            'IDENTIFY': [
                'Asset inventory needed for vulnerable components',
                'Risk assessment for critical/high findings'
            ],
            'PROTECT': [
                f'{self.metrics["by_severity"]["critical"] + self.metrics["by_severity"]["high"]} vulnerabilities need protection controls',
                'Implement security headers and CSP policies'
            ],
            'DETECT': [
                'Continuous vulnerability scanning required',
                'SAST/DAST/SCA integration in CI/CD'
            ],
            'RESPOND': [
                f'{self.metrics["remediable_count"]} vulnerabilities have remediation actions',
                'Incident response procedures for exploitation attempts'
            ],
            'RECOVER': [
                'Backup and recovery procedures for compromised components',
                'Component update and rollback procedures'
            ]
        }
    
    def _map_to_iso27001(self) -> Dict[str, List[str]]:
        """Map findings to ISO 27001:2022 controls"""
        return {
            'A.8.8_Technical_vulnerability_management': [
                f'{len(self.vulnerabilities)} vulnerabilities requiring management',
                'Regular vulnerability assessments implemented'
            ],
            'A.8.9_Configuration_management': [
                'Security configuration issues identified in DAST',
                'Secure configuration baselines needed'
            ],
            'A.8.16_Monitoring': [
                'Continuous security monitoring via SAST/DAST/SCA',
                'Alert mechanisms for new vulnerabilities'
            ],
            'A.8.26_Application_security': [
                f'{self.metrics["by_source"].get("SAST", 0)} code-level vulnerabilities found',
                'Secure development lifecycle improvements needed'
            ]
        }
    
    def _extract_compliance_requirements(self) -> Dict[str, Any]:
        """Extract compliance requirements from findings"""
        requirements = {
            'immediate_action_required': [],
            'short_term': [],
            'long_term': [],
            'governance': []
        }
        
        critical_high = self.metrics['by_severity']['critical'] + self.metrics['by_severity']['high']
        
        if critical_high > 0:
            requirements['immediate_action_required'].append({
                'requirement': 'Remediate critical/high vulnerabilities',
                'count': critical_high,
                'timeframe': '0-7 days'
            })
        
        if self.metrics['by_severity']['medium'] > 0:
            requirements['short_term'].append({
                'requirement': 'Address medium severity issues',
                'count': self.metrics['by_severity']['medium'],
                'timeframe': '30 days'
            })
        
        requirements['governance'].append({
            'requirement': 'Establish vulnerability management policy',
            'based_on': ['NIST CSF', 'ISO 27001'],
            'priority': 'HIGH' if critical_high > 0 else 'MEDIUM'
        })
        
        return requirements
    
    def export_results(self, output_dir: str = "./reports/global"):
        """Export all parsed results"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'metrics': self.metrics,
            'security_posture': self.security_posture,
            'llm_context': self.prepare_llm_context()
        }
        
        # Full JSON export
        with open(output_path / 'parsed_security_report.json', 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Summary JSON
        summary = {
            'timestamp': results['timestamp'],
            'metrics': self.metrics,
            'security_posture': self.security_posture
        }
        with open(output_path / 'summary.json', 'w') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        # LLM context (for policy generation)
        with open(output_path / 'llm_context.json', 'w') as f:
            json.dump(results['llm_context'], f, indent=2, ensure_ascii=False)
        
        # Markdown report
        self._generate_markdown_report(output_path / 'SECURITY_REPORT.md', results)
        
        print(f"\n📁 Results exported to: {output_path}/")
        print(f"  • parsed_security_report.json (complete)")
        print(f"  • summary.json (metrics)")
        print(f"  • llm_context.json (for policy generation)")
        print(f"  • SECURITY_REPORT.md (human-readable)")
    
    def _generate_markdown_report(self, path: Path, results: Dict):
        """Generate detailed markdown report"""
        lines = [
            "# 🔒 Comprehensive Security Analysis Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Vulnerabilities:** {self.metrics['total_vulnerabilities']}",
            f"**Risk Level:** {self.security_posture['risk_level']}",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
            f"- **Risk Score:** {self.security_posture['risk_score']}/100",
            f"- **Critical Vulnerabilities:** {self.metrics['by_severity']['critical']}",
            f"- **High Severity:** {self.metrics['by_severity']['high']}",
            f"- **Medium Severity:** {self.metrics['by_severity']['medium']}",
            f"- **Remediable:** {self.metrics['remediable_count']} ({self.metrics['remediation_rate']}%)",
            "",
            "## 🎯 Immediate Actions Required",
            ""
        ]
        
        for rec in self.security_posture['recommended_actions']:
            lines.append(f"- {rec}")
        
        lines.extend([
            "",
            "## 📈 Vulnerability Breakdown",
            "",
            "### By Source",
            ""
        ])
        
        for source, count in self.metrics['by_source'].items():
            lines.append(f"- **{source}:** {count}")
        
        lines.extend([
            "",
            "### By Category",
            ""
        ])
        
        for category, count in sorted(self.metrics['by_category'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- **{category}:** {count}")
        
        lines.extend([
            "",
            "## 🚨 Critical & High Severity Findings",
            ""
        ])
        
        critical_vulns = [v for v in self.vulnerabilities if v.severity.lower() in ['critical', 'high']]
        for i, v in enumerate(critical_vulns[:15], 1):
            lines.extend([
                f"### {i}. {v.title}",
                f"- **Severity:** {v.severity.upper()}",
                f"- **Source:** {v.source}",
                f"- **Component:** {v.affected_component}",
                f"- **Category:** {v.category}",
                f"- **Remediation:** {v.remediation}",
                ""
            ])
        
        lines.extend([
            "## 🏛️ Compliance Framework Alignment",
            "",
            "### NIST CSF 2.0",
            ""
        ])
        
        for function, items in self.security_posture['nist_csf_alignment'].items():
            lines.append(f"#### {function}")
            for item in items:
                lines.append(f"- {item}")
            lines.append("")
        
        lines.extend([
            "### ISO 27001:2022",
            ""
        ])
        
        for control, items in self.security_posture['iso27001_alignment'].items():
            lines.append(f"#### {control}")
            for item in items:
                lines.append(f"- {item}")
            lines.append("")
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))


def main():
    """Main execution"""
    print("=" * 80)
    print("🔐 Advanced Security Reports Parser")
    print("Preparing data for LLM-based policy generation")
    print("=" * 80)
    print()
    
    reports_dir = os.getenv('REPORTS_DIR', './reports')
    parser = AdvancedSecurityParser(reports_dir=reports_dir)
    
    try:
        results = parser.parse_all()
        parser.export_results()
        
        print("\n" + "=" * 80)
        print("✅ Parsing Completed Successfully!")
        print("=" * 80)
        print(f"\n📊 Summary:")
        print(f"  • Total vulnerabilities: {parser.metrics['total_vulnerabilities']}")
        print(f"  • Risk level: {parser.security_posture['risk_level']}")
        print(f"  • Critical: {parser.metrics['by_severity']['critical']}")
        print(f"  • High: {parser.metrics['by_severity']['high']}")
        print(f"  • Remediable: {parser.metrics['remediable_count']}")
        
        print("\n📁 Generated files ready for LLM policy generation:")
        print("  • llm_context.json - Input for policy generation")
        print("  • parsed_security_report.json - Complete analysis")
        print("  • SECURITY_REPORT.md - Human-readable report")
        
        # Exit code based on severity
        if parser.metrics['by_severity']['critical'] > 0:
            print(f"\n⚠️  WARNING: {parser.metrics['by_severity']['critical']} critical vulnerabilities found!")
            sys.exit(1)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()