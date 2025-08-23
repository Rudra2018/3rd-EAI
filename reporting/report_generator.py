#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Report Generator with AI-Powered Insights
Comprehensive vulnerability reporting with AI analysis and professional formatting
"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import base64
from io import BytesIO

# PDF and HTML generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from jinja2 import Template, Environment, FileSystemLoader
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Plotting for charts
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class ReportConfig:
    """Report generation configuration"""
    title: str = "API Security Assessment Report"
    company_name: str = "Security Assessment"
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_recommendations: bool = True
    include_charts: bool = True
    include_ai_insights: bool = True
    output_format: str = "both"  # pdf, html, both
    template_style: str = "professional"  # professional, minimal, detailed

class EnhancedReportGenerator:
    """
    Advanced report generator with AI-powered analysis and insights
    Features:
    - Professional PDF and HTML report generation
    - AI-powered executive summaries and recommendations
    - Interactive charts and visualizations
    - Customizable templates and styling
    - Multi-format output support
    - Comprehensive vulnerability analysis
    """
    
    def __init__(self, output_dir: str = "reports", ai_enhanced: bool = True):
        self.output_dir = output_dir
        self.ai_enhanced = ai_enhanced and AI_AVAILABLE
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "assets"), exist_ok=True)
        
        # AI coordinator
        self.ai_coordinator = None
        if self.ai_enhanced:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
                log.info("✅ AI-enhanced reporting enabled")
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")
                self.ai_enhanced = False
        
        # Report templates
        self.templates = self._load_templates()
        
        # Initialize plotting style
        if PLOTTING_AVAILABLE:
            plt.style.use('seaborn-v0_8-whitegrid')
            sns.set_palette("husl")

    def _load_templates(self) -> Dict[str, str]:
        """Load report templates"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .container { max-width: 1200px; margin: 0 auto; background: white; }
        .section { margin: 30px 0; padding: 20px; border-left: 4px solid #667eea; }
        .section h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .vulnerability { margin: 15px 0; padding: 15px; border-radius: 5px; }
        .critical { background: #ffebee; border-left: 4px solid #f44336; }
        .high { background: #fff3e0; border-left: 4px solid #ff9800; }
        .medium { background: #e8f5e8; border-left: 4px solid #4caf50; }
        .low { background: #e3f2fd; border-left: 4px solid #2196f3; }
        .info { background: #f5f5f5; border-left: 4px solid #9e9e9e; }
        .chart-container { text-align: center; margin: 20px 0; }
        .recommendation { background: #f0f8ff; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .ai-insight { background: linear-gradient(135deg, #667eea20, #764ba220); padding: 15px; border-radius: 10px; margin: 15px 0; }
        .footer { text-align: center; padding: 20px; color: #666; border-top: 1px solid #eee; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <p>{{ subtitle }}</p>
            <p>Generated on {{ generation_date }}</p>
        </div>
        
        {% if executive_summary %}
        <div class="section">
            <h2>🎯 Executive Summary</h2>
            {{ executive_summary|safe }}
        </div>
        {% endif %}
        
        {% if ai_insights %}
        <div class="ai-insight">
            <h2>🧠 AI-Powered Analysis</h2>
            {{ ai_insights|safe }}
        </div>
        {% endif %}
        
        <div class="section">
            <h2>📊 Vulnerability Summary</h2>
            {{ vulnerability_summary|safe }}
        </div>
        
        {% if charts %}
        <div class="section">
            <h2>📈 Security Metrics</h2>
            {{ charts|safe }}
        </div>
        {% endif %}
        
        <div class="section">
            <h2>🚨 Detailed Findings</h2>
            {{ detailed_findings|safe }}
        </div>
        
        {% if recommendations %}
        <div class="section">
            <h2>💡 Recommendations</h2>
            {{ recommendations|safe }}
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Report generated by Rudra's Third Eye AI - Enhanced API Security Scanner</p>
            <p>© 2025 - Confidential Security Assessment</p>
        </div>
    </div>
</body>
</html>
"""
        
        return {"html": html_template}

    async def generate_comprehensive_report(self, scan_results: List[Dict[str, Any]], 
                                          config: Optional[ReportConfig] = None) -> Dict[str, str]:
        """Generate comprehensive security report with AI enhancement"""
        try:
            if not config:
                config = ReportConfig()
            
            log.info(f"📄 Generating comprehensive report for {len(scan_results)} results")
            
            # Analyze scan results
            analysis = await self._analyze_scan_results(scan_results)
            
            # Generate AI-powered insights
            ai_insights = {}
            if self.ai_enhanced:
                ai_insights = await self._generate_ai_report_insights(scan_results, analysis)
            
            # Create report sections
            report_data = await self._build_report_data(scan_results, analysis, ai_insights, config)
            
            # Generate outputs
            output_files = {}
            
            if config.output_format in ["html", "both"]:
                html_file = await self._generate_html_report(report_data, config)
                output_files["html"] = html_file
            
            if config.output_format in ["pdf", "both"] and PDF_AVAILABLE:
                pdf_file = await self._generate_pdf_report(report_data, config)
                output_files["pdf"] = pdf_file
            
            # Generate JSON report for API consumption
            json_file = await self._generate_json_report(report_data, config)
            output_files["json"] = json_file
            
            log.info(f"✅ Report generation complete: {list(output_files.keys())}")
            return output_files
            
        except Exception as e:
            log.error(f"Report generation failed: {e}")
            return {"error": str(e)}

    async def _analyze_scan_results(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze scan results for report generation"""
        analysis = {
            "total_endpoints": len(scan_results),
            "total_vulnerabilities": 0,
            "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "vulnerability_types": {},
            "affected_endpoints": 0,
            "average_response_time": 0,
            "success_rate": 0,
            "risk_score": 0
        }
        
        total_response_time = 0
        successful_scans = 0
        
        for result in scan_results:
            # Count vulnerabilities
            vulnerabilities = result.get("vulnerabilities", [])
            analysis["total_vulnerabilities"] += len(vulnerabilities)
            
            if vulnerabilities:
                analysis["affected_endpoints"] += 1
            
            # Analyze severity distribution
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Info")
                if severity in analysis["severity_distribution"]:
                    analysis["severity_distribution"][severity] += 1
                
                # Count vulnerability types
                vuln_type = vuln.get("type", "Unknown")
                analysis["vulnerability_types"][vuln_type] = analysis["vulnerability_types"].get(vuln_type, 0) + 1
            
            # Response time analysis
            response_time = result.get("response_time", 0)
            total_response_time += response_time
            
            # Success rate
            if result.get("status_code", 0) > 0:
                successful_scans += 1
        
        # Calculate averages and rates
        if analysis["total_endpoints"] > 0:
            analysis["average_response_time"] = total_response_time / analysis["total_endpoints"]
            analysis["success_rate"] = successful_scans / analysis["total_endpoints"]
        
        # Calculate risk score
        analysis["risk_score"] = self._calculate_risk_score(analysis)
        
        return analysis

    def _calculate_risk_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-10)"""
        severity_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Info": 1}
        
        total_weighted_score = 0
        for severity, count in analysis["severity_distribution"].items():
            total_weighted_score += count * severity_weights.get(severity, 0)
        
        # Normalize to 0-10 scale
        max_possible_score = analysis["total_endpoints"] * 10
        if max_possible_score > 0:
            risk_score = (total_weighted_score / max_possible_score) * 10
        else:
            risk_score = 0
        
        return min(risk_score, 10)

    async def _generate_ai_report_insights(self, scan_results: List[Dict[str, Any]], 
                                         analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered report insights"""
        if not self.ai_coordinator:
            return {}
        
        try:
            # Prepare data for AI analysis
            vulnerability_summary = []
            for result in scan_results[:20]:  # Limit for prompt size
                vulnerabilities = result.get("vulnerabilities", [])
                if vulnerabilities:
                    vulnerability_summary.append({
                        "endpoint": result.get("endpoint", ""),
                        "method": result.get("method", "GET"),
                        "vulnerabilities": [
                            {"type": v.get("type"), "severity": v.get("severity")}
                            for v in vulnerabilities
                        ]
                    })
            
            prompt = f"""Generate comprehensive security report insights:

Scan Analysis:
- Total Endpoints: {analysis['total_endpoints']}
- Total Vulnerabilities: {analysis['total_vulnerabilities']}
- Risk Score: {analysis['risk_score']:.1f}/10
- Severity Distribution: {analysis['severity_distribution']}
- Top Vulnerability Types: {dict(list(analysis['vulnerability_types'].items())[:5])}

Sample Vulnerabilities:
{json.dumps(vulnerability_summary[:10], indent=2)}

Generate insights as JSON:
{{
  "executive_summary": {{
    "overall_security_posture": "excellent|good|moderate|poor|critical",
    "key_findings": ["finding1", "finding2", "finding3"],
    "business_impact": "impact_description",
    "urgency_level": "immediate|high|medium|low"
  }},
  "technical_analysis": {{
    "attack_surface_assessment": "description",
    "vulnerability_trends": ["trend1", "trend2"],
    "security_gaps": ["gap1", "gap2"],
    "compliance_status": "compliant|partially_compliant|non_compliant"
  }},
  "strategic_recommendations": {{
    "immediate_actions": ["action1", "action2"],
    "short_term_goals": ["goal1", "goal2"],
    "long_term_strategy": "strategy_description",
    "resource_requirements": "requirements"
  }},
  "risk_assessment": {{
    "critical_risks": ["risk1", "risk2"],
    "business_risks": ["risk1", "risk2"],
    "mitigation_priorities": ["priority1", "priority2"]
  }}
}}
"""
            
            request = AIRequest(
                task_type="report_insights",
                prompt=prompt,
                temperature=0.2,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_insights(response.content)
            
        except Exception as e:
            log.error(f"AI report insights generation failed: {e}")
        
        return {}

    def _parse_ai_insights(self, content: str) -> Dict[str, Any]:
        """Parse AI insights response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI insights: {e}")
        
        return {}

    async def _build_report_data(self, scan_results: List[Dict[str, Any]], 
                               analysis: Dict[str, Any], 
                               ai_insights: Dict[str, Any],
                               config: ReportConfig) -> Dict[str, Any]:
        """Build comprehensive report data structure"""
        
        report_data = {
            "title": config.title,
            "subtitle": f"Assessment for {config.company_name}",
            "generation_date": datetime.now().strftime("%B %d, %Y at %I:%M %p"),
            "config": config,
            "analysis": analysis,
            "ai_insights": ai_insights,
            "scan_results": scan_results
        }
        
        # Generate report sections
        if config.include_executive_summary:
            report_data["executive_summary"] = await self._generate_executive_summary(analysis, ai_insights)
        
        report_data["vulnerability_summary"] = self._generate_vulnerability_summary(analysis)
        
        if config.include_charts and PLOTTING_AVAILABLE:
            report_data["charts"] = await self._generate_charts(analysis, scan_results)
        
        report_data["detailed_findings"] = self._generate_detailed_findings(scan_results)
        
        if config.include_recommendations:
            report_data["recommendations"] = await self._generate_recommendations(analysis, ai_insights)
        
        return report_data

    async def _generate_executive_summary(self, analysis: Dict[str, Any], 
                                        ai_insights: Dict[str, Any]) -> str:
        """Generate executive summary"""
        summary_parts = []
        
        # Overall assessment
        total_vulns = analysis["total_vulnerabilities"]
        total_endpoints = analysis["total_endpoints"]
        risk_score = analysis["risk_score"]
        
        if risk_score >= 7:
            overall_status = "CRITICAL - Immediate attention required"
            status_class = "critical"
        elif risk_score >= 5:
            overall_status = "HIGH RISK - Prompt remediation needed"
            status_class = "high"
        elif risk_score >= 3:
            overall_status = "MODERATE RISK - Address in near term"
            status_class = "medium"
        else:
            overall_status = "LOW RISK - Monitor and maintain"
            status_class = "low"
        
        summary_parts.append(f"""
        <div class="vulnerability {status_class}">
            <h3>Overall Security Status: {overall_status}</h3>
            <p><strong>Risk Score:</strong> {risk_score:.1f}/10</p>
            <p><strong>Endpoints Assessed:</strong> {total_endpoints}</p>
            <p><strong>Vulnerabilities Identified:</strong> {total_vulns}</p>
            <p><strong>Affected Endpoints:</strong> {analysis['affected_endpoints']} ({(analysis['affected_endpoints']/max(total_endpoints,1)*100):.1f}%)</p>
        </div>
        """)
        
        # AI insights
        if ai_insights:
            exec_summary = ai_insights.get("executive_summary", {})
            if exec_summary:
                summary_parts.append(f"""
                <div class="ai-insight">
                    <h4>🧠 AI Analysis Highlights</h4>
                    <p><strong>Security Posture:</strong> {exec_summary.get('overall_security_posture', 'Unknown').title()}</p>
                    <p><strong>Business Impact:</strong> {exec_summary.get('business_impact', 'Assessment pending')}</p>
                    <p><strong>Urgency Level:</strong> {exec_summary.get('urgency_level', 'medium').title()}</p>
                </div>
                """)
        
        # Key statistics
        critical_count = analysis["severity_distribution"].get("Critical", 0)
        high_count = analysis["severity_distribution"].get("High", 0)
        
        if critical_count > 0 or high_count > 0:
            summary_parts.append(f"""
            <div class="vulnerability high">
                <h4>⚠️ Priority Attention Required</h4>
                <p>Critical Issues: <strong>{critical_count}</strong></p>
                <p>High Risk Issues: <strong>{high_count}</strong></p>
                <p>These vulnerabilities pose significant security risks and should be addressed immediately.</p>
            </div>
            """)
        
        return "\n".join(summary_parts)

    def _generate_vulnerability_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate vulnerability summary section"""
        summary_parts = []
        
        # Severity distribution table
        severity_data = analysis["severity_distribution"]
        summary_parts.append("""
        <table>
            <thead>
                <tr><th>Severity Level</th><th>Count</th><th>Percentage</th></tr>
            </thead>
            <tbody>
        """)
        
        total_vulns = sum(severity_data.values())
        for severity, count in severity_data.items():
            percentage = (count / max(total_vulns, 1)) * 100
            summary_parts.append(f"""
                <tr>
                    <td><span class="severity-{severity.lower()}">{severity}</span></td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
            """)
        
        summary_parts.append("</tbody></table>")
        
        # Top vulnerability types
        if analysis["vulnerability_types"]:
            summary_parts.append("<h4>Most Common Vulnerability Types</h4>")
            sorted_types = sorted(analysis["vulnerability_types"].items(), key=lambda x: x[1], reverse=True)
            
            summary_parts.append("<ul>")
            for vuln_type, count in sorted_types[:5]:
                percentage = (count / max(total_vulns, 1)) * 100
                summary_parts.append(f"<li><strong>{vuln_type}</strong>: {count} instances ({percentage:.1f}%)</li>")
            summary_parts.append("</ul>")
        
        return "\n".join(summary_parts)

    async def _generate_charts(self, analysis: Dict[str, Any], 
                             scan_results: List[Dict[str, Any]]) -> str:
        """Generate charts and visualizations"""
        if not PLOTTING_AVAILABLE:
            return "<p>Charts not available - matplotlib not installed</p>"
        
        chart_html = []
        
        try:
            # Severity distribution pie chart
            severity_chart = await self._create_severity_chart(analysis["severity_distribution"])
            if severity_chart:
                chart_html.append(f'<div class="chart-container"><img src="data:image/png;base64,{severity_chart}" alt="Severity Distribution"></div>')
            
            # Vulnerability types bar chart
            if analysis["vulnerability_types"]:
                types_chart = await self._create_vulnerability_types_chart(analysis["vulnerability_types"])
                if types_chart:
                    chart_html.append(f'<div class="chart-container"><img src="data:image/png;base64,{types_chart}" alt="Vulnerability Types"></div>')
            
            # Response time distribution
            response_times = [r.get("response_time", 0) for r in scan_results if r.get("response_time")]
            if response_times:
                response_chart = await self._create_response_time_chart(response_times)
                if response_chart:
                    chart_html.append(f'<div class="chart-container"><img src="data:image/png;base64,{response_chart}" alt="Response Times"></div>')
            
        except Exception as e:
            log.error(f"Chart generation failed: {e}")
            chart_html.append("<p>Chart generation encountered errors</p>")
        
        return "\n".join(chart_html)

    async def _create_severity_chart(self, severity_data: Dict[str, int]) -> Optional[str]:
        """Create severity distribution pie chart"""
        try:
            # Filter out zero values
            filtered_data = {k: v for k, v in severity_data.items() if v > 0}
            
            if not filtered_data:
                return None
            
            fig, ax = plt.subplots(figsize=(8, 6))
            
            colors = {'Critical': '#f44336', 'High': '#ff9800', 'Medium': '#ffeb3b', 'Low': '#4caf50', 'Info': '#2196f3'}
            chart_colors = [colors.get(k, '#9e9e9e') for k in filtered_data.keys()]
            
            wedges, texts, autotexts = ax.pie(
                filtered_data.values(), 
                labels=filtered_data.keys(),
                colors=chart_colors,
                autopct='%1.1f%%',
                startangle=90
            )
            
            ax.set_title('Vulnerability Severity Distribution', fontsize=14, fontweight='bold')
            
            # Convert to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            plt.close()
            return image_base64
            
        except Exception as e:
            log.error(f"Severity chart creation failed: {e}")
            return None

    async def _create_vulnerability_types_chart(self, types_data: Dict[str, int]) -> Optional[str]:
        """Create vulnerability types bar chart"""
        try:
            # Get top 10 vulnerability types
            sorted_types = sorted(types_data.items(), key=lambda x: x[1], reverse=True)[:10]
            
            if not sorted_types:
                return None
            
            fig, ax = plt.subplots(figsize=(10, 6))
            
            types, counts = zip(*sorted_types)
            bars = ax.barh(types, counts)
            
            # Color bars
            colors = plt.cm.Set3(range(len(bars)))
            for bar, color in zip(bars, colors):
                bar.set_color(color)
            
            ax.set_title('Top Vulnerability Types', fontsize=14, fontweight='bold')
            ax.set_xlabel('Count')
            
            # Add value labels on bars
            for i, (bar, count) in enumerate(zip(bars, counts)):
                ax.text(count + 0.1, i, str(count), va='center')
            
            plt.tight_layout()
            
            # Convert to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            plt.close()
            return image_base64
            
        except Exception as e:
            log.error(f"Types chart creation failed: {e}")
            return None

    async def _create_response_time_chart(self, response_times: List[float]) -> Optional[str]:
        """Create response time distribution chart"""
        try:
            if not response_times:
                return None
            
            fig, ax = plt.subplots(figsize=(10, 6))
            
            ax.hist(response_times, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            ax.set_title('Response Time Distribution', fontsize=14, fontweight='bold')
            ax.set_xlabel('Response Time (seconds)')
            ax.set_ylabel('Frequency')
            
            # Add statistics
            mean_time = sum(response_times) / len(response_times)
            ax.axvline(mean_time, color='red', linestyle='--', label=f'Mean: {mean_time:.2f}s')
            ax.legend()
            
            plt.tight_layout()
            
            # Convert to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            plt.close()
            return image_base64
            
        except Exception as e:
            log.error(f"Response time chart creation failed: {e}")
            return None

    def _generate_detailed_findings(self, scan_results: List[Dict[str, Any]]) -> str:
        """Generate detailed findings section"""
        findings_html = []
        
        # Group vulnerabilities by severity
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        vulnerabilities_by_severity = {sev: [] for sev in severity_order}
        
        for result in scan_results:
            endpoint = result.get("endpoint", "Unknown")
            method = result.get("method", "GET")
            
            for vuln in result.get("vulnerabilities", []):
                vuln_with_context = vuln.copy()
                vuln_with_context["endpoint"] = endpoint
                vuln_with_context["method"] = method
                
                severity = vuln.get("severity", "Info")
                if severity in vulnerabilities_by_severity:
                    vulnerabilities_by_severity[severity].append(vuln_with_context)
        
        # Generate findings by severity
        for severity in severity_order:
            vulns = vulnerabilities_by_severity[severity]
            if not vulns:
                continue
            
            findings_html.append(f"<h3>{severity} Severity Vulnerabilities ({len(vulns)})</h3>")
            
            for i, vuln in enumerate(vulns, 1):
                severity_class = severity.lower()
                
                findings_html.append(f"""
                <div class="vulnerability {severity_class}">
                    <h4>{i}. {vuln.get('type', 'Unknown Vulnerability')}</h4>
                    <p><strong>Endpoint:</strong> {vuln.get('method')} {vuln.get('endpoint')}</p>
                    <p><strong>Severity:</strong> {vuln.get('severity')}</p>
                    <p><strong>Confidence:</strong> {vuln.get('confidence', 'Unknown')}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                    {f'<p><strong>Evidence:</strong> {vuln.get("evidence")}</p>' if vuln.get('evidence') else ''}
                    {f'<p><strong>AI Analysis:</strong> {vuln.get("ai_analysis")}</p>' if vuln.get('ai_analysis') else ''}
                </div>
                """)
        
        return "\n".join(findings_html)

    async def _generate_recommendations(self, analysis: Dict[str, Any], 
                                      ai_insights: Dict[str, Any]) -> str:
        """Generate recommendations section"""
        recommendations_

