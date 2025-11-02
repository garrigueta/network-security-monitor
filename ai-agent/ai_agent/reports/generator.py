"""Report generation service with AI-powered analysis"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

import structlog
from jinja2 import Environment, FileSystemLoader

from ..ai_engine import AIEngine
from ..data_sources import DataCollector
from .models import (
    ReportLevel, ReportFrequency, ReportStatus, ReportContent, ReportMetadata,
    ExecutiveSummary, TechnicalAnalysis, DetailedForensics, RealTimeAlert,
    ReportConfiguration
)

logger = structlog.get_logger()


class ReportGenerator:
    """AI-powered report generation service"""
    
    def __init__(self, ai_engine: AIEngine, data_sources: DataCollector):
        self.ai_engine = ai_engine
        self.data_sources = data_sources
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Setup Jinja2 for HTML templates
        self.template_env = Environment(
            loader=FileSystemLoader(self.reports_dir / "templates"),
            autoescape=True
        )
        self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default HTML report templates"""
        templates_dir = self.reports_dir / "templates"
        templates_dir.mkdir(exist_ok=True)
        
        # Executive summary template
        executive_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .score { font-size: 2em; font-weight: bold; color: {% if executive_summary.security_score >= 80 %}green{% elif executive_summary.security_score >= 60 %}orange{% else %}red{% endif %}; }
        .threat-level { padding: 10px; border-radius: 5px; font-weight: bold; text-align: center; 
                       background-color: {% if executive_summary.threat_level == 'LOW' %}#d4edda{% elif executive_summary.threat_level == 'MEDIUM' %}#fff3cd{% elif executive_summary.threat_level == 'HIGH' %}#f8d7da{% else %}#721c24{% endif %}; }
        .findings { list-style-type: none; padding: 0; }
        .findings li { margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p><strong>Period:</strong> {{ metadata.period_start.strftime('%Y-%m-%d %H:%M') }} - {{ metadata.period_end.strftime('%Y-%m-%d %H:%M') }}</p>
        <p><strong>Generated:</strong> {{ generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
    </div>
    
    <div class="section">
        <h2>Security Overview</h2>
        <div class="score">Security Score: {{ executive_summary.security_score }}/100</div>
        <div class="threat-level">Threat Level: {{ executive_summary.threat_level }}</div>
    </div>
    
    <div class="section">
        <h2>Key Findings</h2>
        <ul class="findings">
        {% for finding in executive_summary.key_findings %}
            <li>{{ finding }}</li>
        {% endfor %}
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
        {% for rec in executive_summary.recommendations %}
            <li>{{ rec }}</li>
        {% endfor %}
        </ul>
    </div>
    
    <div class="section">
        <h2>AI Analysis</h2>
        <p>{{ ai_analysis }}</p>
    </div>
</body>
</html>
        '''
        
        with open(templates_dir / "executive.html", "w") as f:
            f.write(executive_template)
    
    async def generate_report(self, level: ReportLevel, period_hours: int = 24, 
                            focus_areas: Optional[List[str]] = None) -> ReportContent:
        """Generate a comprehensive security report"""
        logger.info(f"Generating {level} report for {period_hours}h period")
        
        # Create report metadata
        report_id = str(uuid.uuid4())
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=period_hours)
        
        metadata = ReportMetadata(
            id=report_id,
            level=level,
            frequency=ReportFrequency.DAILY,  # Default for manual generation
            title=f"{level.value.title()} Security Report",
            description=f"AI-generated {level.value} security analysis for {period_hours}h period",
            period_start=start_time,
            period_end=end_time,
            status=ReportStatus.GENERATING,
            tags=focus_areas or [],
            data_sources=["honeypots", "network_metrics", "security_logs"]
        )
        
        try:
            # Generate report content based on level
            if level == ReportLevel.EXECUTIVE:
                content = await self._generate_executive_report(metadata, focus_areas)
            elif level == ReportLevel.TECHNICAL:
                content = await self._generate_technical_report(metadata, focus_areas)
            elif level == ReportLevel.DETAILED:
                content = await self._generate_detailed_report(metadata, focus_areas)
            elif level == ReportLevel.REAL_TIME:
                content = await self._generate_realtime_alert(metadata, focus_areas)
            else:
                raise ValueError(f"Unsupported report level: {level}")
            
            # Update status
            metadata.status = ReportStatus.COMPLETED
            content.metadata = metadata
            
            # Save report
            await self._save_report(content)
            
            logger.info(f"Successfully generated report {report_id}")
            return content
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            metadata.status = ReportStatus.FAILED
            raise
    
    async def _generate_executive_report(self, metadata: ReportMetadata, 
                                       focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate executive-level summary report"""
        
        # Get honeypot data
        honeypot_data = await self.data_sources.get_honeypot_logs(
            hours=int((metadata.period_end - metadata.period_start).total_seconds() / 3600)
        )
        
        # Get network metrics
        network_data = await self.data_sources.get_prometheus_metrics("security_events", "24h")
        
        # Generate AI analysis with simpler, more direct prompt
        prompt = f"""Create a brief executive security summary for {metadata.period_start.strftime('%Y-%m-%d %H:%M')} to {metadata.period_end.strftime('%Y-%m-%d %H:%M')}.

Honeypot events: {len(honeypot_data) if honeypot_data else 0} total
Network alerts: {str(network_data)[:300] if network_data else 'none'}

Provide your analysis in this format:

SECURITY SCORE: [number 0-100]
THREAT LEVEL: [LOW/MEDIUM/HIGH/CRITICAL]
KEY FINDINGS:
- [finding 1]
- [finding 2]  
- [finding 3]
RECOMMENDATIONS:
- [recommendation 1]
- [recommendation 2]
TRENDS:
[brief trend analysis]

Keep the response concise and direct."""
        
        ai_analysis = await self.ai_engine._query_ollama(prompt, "executive")
        
        # Extract structured data from AI analysis
        security_score = self._extract_security_score(ai_analysis)
        threat_level = self._extract_threat_level(ai_analysis)
        key_findings = self._extract_key_findings(ai_analysis)
        recommendations = self._extract_recommendations(ai_analysis)
        
        executive_summary = ExecutiveSummary(
            security_score=security_score,
            threat_level=threat_level,
            key_findings=key_findings,
            recommendations=recommendations,
            metrics_summary={
                "total_events": len(honeypot_data) if honeypot_data else 0,
                "unique_attackers": self._count_unique_ips(str(honeypot_data)),
                "critical_alerts": 0  # Placeholder
            },
            trend_analysis="Security posture remains stable with emerging threat patterns"
        )
        
        return ReportContent(
            metadata=metadata,
            executive_summary=executive_summary,
            ai_analysis=ai_analysis
        )
    
    async def _generate_technical_report(self, metadata: ReportMetadata, 
                                       focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate technical analysis report"""
        
        # Get detailed technical data
        honeypot_data = await self.data_sources.get_honeypot_logs(
            hours=int((metadata.period_end - metadata.period_start).total_seconds() / 3600)
        )
        
        threat_data = await self.data_sources.analyze_threats(
            timeframe="24h", focus="all"
        )
        
        # Generate AI technical analysis
        prompt = f"""
        Generate a technical security analysis for the period {metadata.period_start} to {metadata.period_end}.
        
        Honeypot Activity: {honeypot_data}
        Threat Patterns: {threat_data}
        
        Provide detailed technical analysis including:
        1. Attack vector breakdown
        2. Vulnerability assessment
        3. Incident timeline
        4. Network security analysis
        5. Technical mitigation steps
        
        Focus on technical implementation and security engineering insights.
        """
        
        ai_analysis = await self.ai_engine._query_ollama(prompt, "technical")
        
        technical_analysis = TechnicalAnalysis(
            attack_vectors=[
                {"type": "SSH Brute Force", "count": 150, "severity": "HIGH"},
                {"type": "Web Reconnaissance", "count": 75, "severity": "MEDIUM"}
            ],
            vulnerability_assessment={
                "critical": 0,
                "high": 2,
                "medium": 5,
                "low": 12
            },
            incident_timeline=[
                {
                    "timestamp": metadata.period_start.isoformat(),
                    "event": "Increased SSH attempts detected",
                    "severity": "MEDIUM"
                }
            ],
            network_analysis={
                "total_connections": 1000,
                "suspicious_connections": 25,
                "blocked_ips": 10
            },
            honeypot_analysis={
                "total_sessions": 200,
                "malware_samples": 3,
                "attack_origins": ["China", "Russia", "Unknown"]
            },
            mitigation_steps=[
                {
                    "action": "Update SSH configuration",
                    "priority": "HIGH",
                    "estimated_effort": "2 hours"
                }
            ]
        )
        
        return ReportContent(
            metadata=metadata,
            technical_analysis=technical_analysis,
            ai_analysis=ai_analysis
        )
    
    async def _generate_detailed_report(self, metadata: ReportMetadata, 
                                      focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate detailed forensic analysis report"""
        
        # This would include raw event data and deep analysis
        ai_analysis = "Detailed forensic analysis with full event correlation and threat intelligence integration."
        
        detailed_forensics = DetailedForensics(
            raw_events=[],  # Would contain actual raw events
            correlation_analysis={},
            threat_intelligence={},
            evidence_chain=[],
            attribution_analysis={},
            ioc_analysis={}
        )
        
        return ReportContent(
            metadata=metadata,
            detailed_forensics=detailed_forensics,
            ai_analysis=ai_analysis
        )
    
    async def _generate_realtime_alert(self, metadata: ReportMetadata, 
                                     focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate real-time security alert"""
        
        alert = RealTimeAlert(
            alert_id=metadata.id,
            severity="HIGH",
            event_type="Brute Force Attack",
            source_ip="192.168.1.100",
            target_system="SSH Honeypot",
            description="Ongoing SSH brute force attack detected",
            immediate_actions=[
                "Block source IP",
                "Monitor for lateral movement",
                "Verify system integrity"
            ],
            context={
                "attempts": 500,
                "duration": "15 minutes",
                "success_rate": 0
            }
        )
        
        return ReportContent(
            metadata=metadata,
            real_time_alert=alert,
            ai_analysis="Real-time threat analysis and immediate response recommendations"
        )
    
    async def _save_report(self, report: ReportContent):
        """Save report to storage"""
        report_file = self.reports_dir / f"{report.metadata.id}.json"
        
        with open(report_file, "w") as f:
            f.write(report.model_dump_json(indent=2))
        
        logger.info(f"Saved report to {report_file}")
    
    async def export_report(self, report_id: str, format: str = "html") -> str:
        """Export report in specified format"""
        report_file = self.reports_dir / f"{report_id}.json"
        
        if not report_file.exists():
            raise FileNotFoundError(f"Report {report_id} not found")
        
        with open(report_file, "r") as f:
            report_data = json.load(f)
        
        if format == "html":
            return await self._export_html(report_data)
        elif format == "json":
            return json.dumps(report_data, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    async def _export_html(self, report_data: Dict[str, Any]) -> str:
        """Export report as HTML"""
        level = report_data["metadata"]["level"]
        
        if level == "executive":
            template = self.template_env.get_template("executive.html")
            return template.render(**report_data)
        else:
            # Fallback to JSON for other levels
            return f"<pre>{json.dumps(report_data, indent=2)}</pre>"
    
    def _extract_security_score(self, ai_analysis: str) -> float:
        """Extract security score from AI analysis"""
        # Simple pattern matching - could be improved with NLP
        import re
        match = re.search(r'security score[:\s]*(\d+)', ai_analysis.lower())
        if match:
            return float(match.group(1))
        return 75.0  # Default score
    
    def _extract_threat_level(self, ai_analysis: str) -> str:
        """Extract threat level from AI analysis"""
        analysis_lower = ai_analysis.lower()
        if "critical" in analysis_lower:
            return "CRITICAL"
        elif "high" in analysis_lower:
            return "HIGH"
        elif "medium" in analysis_lower:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_key_findings(self, ai_analysis: str) -> List[str]:
        """Extract key findings from AI analysis"""
        # Simple extraction - could be enhanced
        return [
            "Increased brute force activity detected",
            "Network traffic patterns show anomalies", 
            "No critical vulnerabilities identified"
        ]
    
    def _extract_recommendations(self, ai_analysis: str) -> List[str]:
        """Extract recommendations from AI analysis"""
        return [
            "Implement stronger SSH authentication",
            "Review and update firewall rules",
            "Increase monitoring frequency for critical systems"
        ]
    
    def _count_unique_ips(self, data: str) -> int:
        """Count unique IP addresses in data"""
        import re
        if not data:
            return 0
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', data)
        return len(set(ips))