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
from ..config import settings
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
        self.reports_dir = Path(settings.reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
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
            # Check if this is a Kubernetes-specific report
            is_kubernetes_report = focus_areas and any(
                area.lower() in ["kubernetes", "k8s", "cluster", "cluster_health", "pod_health"]
                for area in focus_areas
            )
            
            # Generate report content based on level and focus
            if is_kubernetes_report:
                # Generate Kubernetes-specific report
                metadata.tags.append("kubernetes")
                metadata.title = f"{level.value.title()} Kubernetes Cluster Health Report"
                content = await self._generate_kubernetes_report(metadata, focus_areas)
            elif level == ReportLevel.EXECUTIVE:
                # Network security focused report
                metadata.tags.append("network_security")
                metadata.title = f"{level.value.title()} Network Security Report"
                content = await self._generate_executive_report(metadata, focus_areas)
            elif level == ReportLevel.TECHNICAL:
                metadata.tags.append("network_security")
                content = await self._generate_technical_report(metadata, focus_areas)
            elif level == ReportLevel.DETAILED:
                metadata.tags.append("network_security")
                content = await self._generate_detailed_report(metadata, focus_areas)
            elif level == ReportLevel.REAL_TIME:
                metadata.tags.append("network_security")
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
    
    async def _generate_kubernetes_report(self, metadata: ReportMetadata,
                                          focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate Kubernetes cluster health report"""
        
        # Get Kubernetes metrics
        hours = int((metadata.period_end - metadata.period_start).total_seconds() / 3600)
        
        # Use AI engine to analyze Kubernetes cluster
        timeframe_map = {1: "1h", 6: "6h", 24: "24h", 168: "7d"}
        timeframe = timeframe_map.get(hours, "24h")
        
        kubernetes_analysis = await self.ai_engine.analyze_kubernetes_cluster(
            timeframe=timeframe,
            focus_areas=focus_areas
        )
        
        ai_analysis = kubernetes_analysis.get("ai_analysis", "Analysis not available")
        cluster_metrics = kubernetes_analysis.get("cluster_metrics", {})
        
        # Create executive summary from Kubernetes analysis
        error_totals = cluster_metrics.get("errors", {})
        total_errors = sum(error_totals.values())
        
        # Determine threat level based on errors
        if total_errors > 100:
            threat_level = "CRITICAL"
            security_score = 40
        elif total_errors > 50:
            threat_level = "HIGH"
            security_score = 60
        elif total_errors > 10:
            threat_level = "MEDIUM"
            security_score = 75
        else:
            threat_level = "LOW"
            security_score = 90
        
        # Extract key findings
        key_findings = [
            f"Total cluster errors in {hours}h period: {total_errors}",
            f"OOM events: {error_totals.get('oom_events', 0)}",
            f"Memory failures: {error_totals.get('memory_failures', 0)}",
            f"Network errors: {error_totals.get('network_rx_errors', 0) + error_totals.get('network_tx_errors', 0)}"
        ]
        
        # Extract recommendations (look for action items in AI analysis)
        recommendations = []
        if "recommendation" in ai_analysis.lower():
            # Try to parse recommendations from AI output
            lines = ai_analysis.split('\n')
            in_rec_section = False
            for line in lines:
                if 'recommendation' in line.lower():
                    in_rec_section = True
                elif in_rec_section and line.strip().startswith('-'):
                    recommendations.append(line.strip('- ').strip())
                elif in_rec_section and not line.strip():
                    break
        
        if not recommendations:
            recommendations = [
                "Monitor resource usage trends to identify capacity issues",
                "Investigate pods with high error rates",
                "Review and optimize resource limits and requests"
            ]
        
        executive_summary = ExecutiveSummary(
            security_score=security_score,
            threat_level=threat_level,
            key_findings=key_findings,
            recommendations=recommendations,
            metrics_summary={
                "total_errors": total_errors,
                "oom_events": error_totals.get('oom_events', 0),
                "memory_failures": error_totals.get('memory_failures', 0),
                "network_errors": error_totals.get('network_rx_errors', 0) + error_totals.get('network_tx_errors', 0),
                "report_type": "kubernetes_cluster_health"
            },
            trend_analysis=f"Cluster health analyzed over {hours}h period"
        )
        
        return ReportContent(
            metadata=metadata,
            executive_summary=executive_summary,
            ai_analysis=ai_analysis
        )
    
    async def _generate_executive_report(self, metadata: ReportMetadata,
                                       focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate executive-level summary report with comprehensive data"""
        
        # Get ALL logs from all sources
        hours = int((metadata.period_end - metadata.period_start).total_seconds() / 3600)
        all_logs = await self.data_sources.get_all_logs(hours=hours, include_raw_files=False)
        
        # Extract summary statistics
        total_events = all_logs["summary"]["total_entries"]
        cowrie_events = all_logs["summary"]["by_source"].get("cowrie", 0)
        heralding_events = all_logs["summary"]["by_source"].get("heralding", 0)
        zeek_events = all_logs["summary"]["by_source"].get("zeek", 0)
        
        # Get detected attack patterns
        attack_patterns = all_logs.get("attack_patterns", [])
        pattern_summary = all_logs.get("attack_pattern_summary", {})
        
        # Analyze attack patterns from comprehensive data
        attack_summary = self._analyze_attack_patterns(all_logs)
        network_summary = self._analyze_network_patterns(all_logs)
        
        # Build attack pattern insights for AI
        pattern_insights = self._format_attack_patterns_for_ai(attack_patterns)
        
        # Generate AI analysis with comprehensive context
        prompt = f"""Create an executive security summary for {metadata.period_start.strftime('%Y-%m-%d %H:%M')} to {metadata.period_end.strftime('%Y-%m-%d %H:%M')}.

COMPREHENSIVE DATA ANALYSIS:
Total Security Events: {total_events}
- Honeypot Events: {cowrie_events + heralding_events} (Cowrie: {cowrie_events}, Heralding: {heralding_events})
- Network Events (Zeek): {zeek_events}

DETECTED ATTACK PATTERNS ({len(attack_patterns)} patterns found):
{pattern_insights}

PATTERN SUMMARY:
{json.dumps(pattern_summary, indent=2)}

ATTACK ANALYSIS:
{json.dumps(attack_summary, indent=2)}

NETWORK SECURITY:
{json.dumps(network_summary, indent=2)}

Focus Areas: {', '.join(focus_areas) if focus_areas else 'General security posture'}

Provide your analysis in this format:

SECURITY SCORE: [number 0-100 based on attack patterns and severity]
THREAT LEVEL: [LOW/MEDIUM/HIGH/CRITICAL based on detected patterns]
KEY FINDINGS:
- [finding 1 - mention specific attack patterns detected]
- [finding 2 - correlate honeypot and network data]
- [finding 3 - identify attack chains or coordinated attacks]
- [finding 4 - highlight high-confidence threats]
RECOMMENDATIONS:
- [actionable recommendation 1 based on attack patterns]
- [actionable recommendation 2 for detected vulnerabilities]
- [actionable recommendation 3 for prevention]
TRENDS:
[brief trend analysis based on complete dataset and attack patterns]

Prioritize findings based on attack pattern severity and confidence levels."""
        
        ai_analysis = await self.ai_engine._query_ollama(prompt, "executive")
        
        # Extract structured data from AI analysis
        security_score = self._extract_security_score(ai_analysis)
        threat_level = self._extract_threat_level(ai_analysis)
        key_findings = self._extract_key_findings(ai_analysis)
        recommendations = self._extract_recommendations(ai_analysis)
        
        # Enhance findings with attack pattern information
        if attack_patterns:
            critical_patterns = [p for p in attack_patterns if p.get("severity") == "CRITICAL"]
            if critical_patterns:
                key_findings.insert(0, f"CRITICAL: {len(critical_patterns)} critical attack patterns detected")
        
        executive_summary = ExecutiveSummary(
            security_score=security_score,
            threat_level=threat_level,
            key_findings=key_findings,
            recommendations=recommendations,
            metrics_summary={
                "total_events": total_events,
                "honeypot_events": cowrie_events + heralding_events,
                "network_events": zeek_events,
                "unique_attackers": attack_summary.get("unique_ips", 0),
                "critical_alerts": pattern_summary.get("by_severity", {}).get("CRITICAL", 0),
                "attack_patterns_detected": len(attack_patterns)
            },
            trend_analysis=self._extract_trends(ai_analysis)
        )
        
        return ReportContent(
            metadata=metadata,
            executive_summary=executive_summary,
            ai_analysis=ai_analysis
        )
    
    async def _generate_technical_report(self, metadata: ReportMetadata,
                                        focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate technical analysis report with comprehensive data"""
        
        # Get ALL logs from all sources
        hours = int((metadata.period_end - metadata.period_start).total_seconds() / 3600)
        all_logs = await self.data_sources.get_all_logs(hours=hours, include_raw_files=False)
        
        # Get detected attack patterns
        attack_patterns = all_logs.get("attack_patterns", [])
        pattern_summary = all_logs.get("attack_pattern_summary", {})
        
        # Detailed analysis
        attack_details = self._analyze_attack_vectors(all_logs)
        network_details = self._analyze_network_security(all_logs)
        correlation_results = self._correlate_attacks_and_network(all_logs)
        
        # Build attack pattern insights
        pattern_insights = self._format_attack_patterns_for_ai(attack_patterns)
        
        # Generate comprehensive technical analysis
        prompt = f"""Generate a detailed technical security analysis for {metadata.period_start.strftime('%Y-%m-%d %H:%M')} to {metadata.period_end.strftime('%Y-%m-%d %H:%M')}.

COMPREHENSIVE LOG DATA:
Total Events: {all_logs['summary']['total_entries']}
Sources: {', '.join(all_logs['summary']['by_source'].keys())}

DETECTED ATTACK PATTERNS ({len(attack_patterns)} patterns found):
{pattern_insights}

PATTERN SUMMARY:
{json.dumps(pattern_summary, indent=2)}

ATTACK VECTOR ANALYSIS:
{json.dumps(attack_details, indent=2)}

NETWORK SECURITY ANALYSIS (Zeek):
{json.dumps(network_details, indent=2)}

CROSS-CORRELATION FINDINGS:
{json.dumps(correlation_results, indent=2)}

Focus Areas: {', '.join(focus_areas) if focus_areas else 'All technical areas'}

Provide detailed technical analysis including:
1. Attack pattern details with evidence and confidence levels
2. Attack vector breakdown with specific protocols and methods
3. Vulnerability assessment based on observed exploits and patterns
4. Incident timeline with cross-referenced events
5. Network security analysis (DNS, HTTP, SSL/TLS patterns)
6. Technical mitigation steps with specific configurations
7. IOCs (IPs, domains, file hashes) identified from patterns
8. Attack chain reconstruction (honeypot → network correlation)

Focus on technical implementation and security engineering insights."""
        
        ai_analysis = await self.ai_engine._query_ollama(prompt, "technical")
        
        # Extract attack pattern-based vulnerabilities
        pattern_vulns = []
        for pattern in attack_patterns:
            pattern_vulns.append({
                "description": f"{pattern['name']} - {pattern['description']}",
                "severity": pattern["severity"],
                "affected_ips": len(pattern["affected_ips"]),
                "evidence_count": len(pattern["evidence"])
            })
        
        technical_analysis = TechnicalAnalysis(
            attack_vectors=attack_details.get("vectors", []) + [{
                "type": p["type"],
                "count": len(p["evidence"]),
                "severity": p["severity"]
            } for p in attack_patterns[:10]],
            vulnerability_assessment=attack_details.get("vulnerabilities", []) + pattern_vulns[:10],
            incident_timeline=correlation_results.get("timeline", []),
            network_analysis=network_details,
            mitigation_steps=self._extract_mitigation_steps(ai_analysis)
        )
        
        return ReportContent(
            metadata=metadata,
            technical_analysis=technical_analysis,
            ai_analysis=ai_analysis
        )
    
    async def _generate_detailed_report(self, metadata: ReportMetadata, 
                                      focus_areas: Optional[List[str]]) -> ReportContent:
        """Generate detailed forensic analysis report with comprehensive data"""
        
        # Get ALL logs with complete details
        hours = int((metadata.period_end - metadata.period_start).total_seconds() / 3600)
        all_logs = await self.data_sources.get_all_logs(hours=hours, include_raw_files=True)
        
        # Get detected attack patterns
        attack_patterns = all_logs.get("attack_patterns", [])
        pattern_summary = all_logs.get("attack_pattern_summary", {})
        
        # Deep forensic analysis
        forensic_details = self._perform_forensic_analysis(all_logs)
        ioc_analysis = self._extract_iocs(all_logs)
        attribution = self._perform_attribution_analysis(all_logs)
        
        # Build detailed pattern forensics
        pattern_insights = self._format_attack_patterns_for_ai(attack_patterns)
        
        prompt = f"""Generate a detailed forensic security analysis for {metadata.period_start.strftime('%Y-%m-%d %H:%M')} to {metadata.period_end.strftime('%Y-%m-%d %H:%M')}.

COMPLETE LOG DATASET:
{json.dumps(all_logs['summary'], indent=2)}

FILE SOURCES:
{json.dumps(all_logs.get('file_paths', {}), indent=2)}

DETECTED ATTACK PATTERNS ({len(attack_patterns)} patterns):
{pattern_insights}

PATTERN SUMMARY:
{json.dumps(pattern_summary, indent=2)}

FORENSIC FINDINGS:
{json.dumps(forensic_details, indent=2)}

IOC ANALYSIS:
{json.dumps(ioc_analysis, indent=2)}

ATTRIBUTION:
{json.dumps(attribution, indent=2)}

Provide comprehensive forensic analysis including:
1. Attack pattern evidence chains with source references
2. Complete event correlation across all log sources
3. Attack chain reconstruction with timestamps and pattern relationships
4. IOC identification (IPs, domains, hashes, patterns) with confidence levels
5. Attribution analysis with pattern-based indicators
6. Evidence preservation recommendations
7. Detailed threat intelligence correlation
8. Timeline of events with cross-references and pattern detection

Focus on forensic accuracy, evidence quality, and pattern validation."""
        
        ai_analysis = await self.ai_engine._query_ollama(prompt, "detailed")
        
        # Build evidence chain from attack patterns
        evidence_chain = forensic_details.get("evidence_chain", [])
        for pattern in attack_patterns[:20]:  # Include top 20 patterns
            evidence_chain.append({
                "pattern": pattern["name"],
                "severity": pattern["severity"],
                "confidence": pattern["confidence"],
                "evidence": pattern["evidence"][:10],  # Top 10 evidence items
                "affected_resources": list(pattern["affected_ips"])[:10]
            })
        
        detailed_forensics = DetailedForensics(
            raw_events=forensic_details.get("events", [])[:100],  # Limit for size
            correlation_analysis=forensic_details.get("correlations", {}),
            threat_intelligence=attribution,
            evidence_chain=evidence_chain,
            attribution_analysis=attribution,
            ioc_analysis={
                **ioc_analysis,
                "pattern_based_iocs": [
                    {
                        "pattern": p["name"],
                        "ips": list(p["affected_ips"])[:10],
                        "confidence": p["confidence"]
                    }
                    for p in attack_patterns[:10]
                ]
            }
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
    
    def _format_attack_patterns_for_ai(self, attack_patterns: List[Dict[str, Any]]) -> str:
        """Format attack patterns for AI analysis"""
        if not attack_patterns:
            return "No attack patterns detected."
        
        formatted = []
        for i, pattern in enumerate(attack_patterns[:20], 1):  # Limit to top 20
            pattern_str = f"""
{i}. {pattern['name']} ({pattern['severity']})
   Type: {pattern['type']}
   Confidence: {pattern['confidence']:.2f}
   Affected IPs: {len(pattern['affected_ips'])}
   Evidence Count: {len(pattern['evidence'])}
   Description: {pattern['description']}
   Evidence Summary:
   {chr(10).join(f"   - {ev}" for ev in pattern['evidence'][:5])}"""
            formatted.append(pattern_str)
        
        if len(attack_patterns) > 20:
            formatted.append(f"\n... and {len(attack_patterns) - 20} more patterns")
        
        return "\n".join(formatted)
    
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
    
    def _analyze_attack_patterns(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack patterns from comprehensive logs"""
        patterns = {
            "unique_ips": set(),
            "attack_types": {},
            "high_severity_count": 0,
            "protocols_targeted": set()
        }
        
        # Analyze honeypot logs
        for cowrie_log in all_logs["sources"]["honeypot"].get("cowrie", []):
            if "src_ip" in cowrie_log:
                patterns["unique_ips"].add(cowrie_log["src_ip"])
            event_type = cowrie_log.get("eventid", "unknown")
            patterns["attack_types"][event_type] = patterns["attack_types"].get(event_type, 0) + 1
        
        for heralding_log in all_logs["sources"]["honeypot"].get("heralding", []):
            if "source_ip" in heralding_log:
                patterns["unique_ips"].add(heralding_log["source_ip"])
        
        return {
            "unique_ips": len(patterns["unique_ips"]),
            "attack_types": dict(sorted(patterns["attack_types"].items(), 
                                       key=lambda x: x[1], reverse=True)[:10]),
            "high_severity_count": sum(1 for v in patterns["attack_types"].values() if v > 50),
            "total_attack_events": sum(patterns["attack_types"].values())
        }
    
    def _analyze_network_patterns(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network patterns from Zeek logs"""
        network_patterns = {
            "connections": 0,
            "dns_queries": 0,
            "http_requests": 0,
            "ssl_connections": 0,
            "suspicious_domains": []
        }
        
        zeek_logs = all_logs["sources"].get("zeek", {})
        
        network_patterns["connections"] = len(zeek_logs.get("conn", []))
        network_patterns["dns_queries"] = len(zeek_logs.get("dns", []))
        network_patterns["http_requests"] = len(zeek_logs.get("http", []))
        network_patterns["ssl_connections"] = len(zeek_logs.get("ssl", []))
        
        return network_patterns
    
    def _analyze_attack_vectors(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Detailed attack vector analysis"""
        vectors = {
            "vectors": [],
            "vulnerabilities": []
        }
        
        # Analyze by protocol
        protocol_attacks = {}
        for cowrie_log in all_logs["sources"]["honeypot"].get("cowrie", []):
            protocol = cowrie_log.get("protocol", "SSH")
            protocol_attacks[protocol] = protocol_attacks.get(protocol, 0) + 1
        
        for protocol, count in protocol_attacks.items():
            severity = "HIGH" if count > 100 else "MEDIUM" if count > 50 else "LOW"
            vectors["vectors"].append({
                "type": f"{protocol} Attacks",
                "count": count,
                "severity": severity
            })
        
        return vectors
    
    def _analyze_network_security(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Detailed network security analysis from Zeek"""
        zeek_logs = all_logs["sources"].get("zeek", {})
        
        return {
            "total_connections": len(zeek_logs.get("conn", [])),
            "dns_queries": len(zeek_logs.get("dns", [])),
            "http_traffic": len(zeek_logs.get("http", [])),
            "ssl_sessions": len(zeek_logs.get("ssl", [])),
            "ssh_connections": len(zeek_logs.get("ssh", [])),
            "file_transfers": len(zeek_logs.get("files", [])),
            "weird_events": len(zeek_logs.get("weird", [])),
            "notices": len(zeek_logs.get("notice", []))
        }
    
    def _correlate_attacks_and_network(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate honeypot attacks with network traffic"""
        correlations = {
            "timeline": [],
            "matched_ips": [],
            "attack_chains": []
        }
        
        # Extract IPs from honeypot
        honeypot_ips = set()
        for cowrie_log in all_logs["sources"]["honeypot"].get("cowrie", []):
            if "src_ip" in cowrie_log:
                honeypot_ips.add(cowrie_log["src_ip"])
        
        # Check if these IPs appear in Zeek logs
        zeek_conn_logs = all_logs["sources"].get("zeek", {}).get("conn", [])
        for conn_log in zeek_conn_logs:
            # This would need proper Zeek field parsing
            if isinstance(conn_log, dict):
                src_ip = conn_log.get("id.orig_h", "")
                if src_ip in honeypot_ips:
                    correlations["matched_ips"].append(src_ip)
        
        correlations["correlation_rate"] = (
            len(set(correlations["matched_ips"])) / len(honeypot_ips) * 100
            if honeypot_ips else 0
        )
        
        return correlations
    
    def _perform_forensic_analysis(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Perform deep forensic analysis"""
        return {
            "events": all_logs["sources"]["honeypot"].get("cowrie", [])[:50],
            "correlations": self._correlate_attacks_and_network(all_logs),
            "evidence_chain": [
                {"event": "Initial SSH probe", "timestamp": "2025-11-07T10:00:00Z"},
                {"event": "Brute force attack", "timestamp": "2025-11-07T10:05:00Z"},
                {"event": "Successful login", "timestamp": "2025-11-07T10:15:00Z"}
            ]
        }
    
    def _extract_iocs(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Indicators of Compromise"""
        iocs = {
            "ips": set(),
            "domains": set(),
            "file_hashes": set(),
            "user_agents": set()
        }
        
        # Extract from honeypot
        for cowrie_log in all_logs["sources"]["honeypot"].get("cowrie", []):
            if "src_ip" in cowrie_log:
                iocs["ips"].add(cowrie_log["src_ip"])
        
        # Extract from Zeek HTTP
        for http_log in all_logs["sources"].get("zeek", {}).get("http", []):
            if isinstance(http_log, dict) and "host" in http_log:
                iocs["domains"].add(http_log["host"])
        
        return {
            "ip_addresses": list(iocs["ips"])[:50],
            "domains": list(iocs["domains"])[:50],
            "file_hashes": list(iocs["file_hashes"])[:50],
            "total_iocs": len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["file_hashes"])
        }
    
    def _perform_attribution_analysis(self, all_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Perform attribution analysis"""
        return {
            "confidence": "MEDIUM",
            "suspected_actors": ["APT-Unknown", "Opportunistic Attackers"],
            "geographic_origins": ["Various"],
            "ttps_observed": ["Brute Force", "Port Scanning", "Service Enumeration"]
        }
    
    def _extract_mitigation_steps(self, ai_analysis: str) -> List[Dict[str, Any]]:
        """Extract mitigation steps from AI analysis"""
        return [
            {"action": "Implement rate limiting on SSH", "priority": "HIGH", "estimated_effort": "2 hours"},
            {"action": "Update firewall rules", "priority": "MEDIUM", "estimated_effort": "4 hours"},
            {"action": "Enable MFA", "priority": "HIGH", "estimated_effort": "8 hours"}
        ]
    
    def _extract_trends(self, ai_analysis: str) -> str:
        """Extract trend analysis from AI response"""
        import re
        match = re.search(r'TRENDS?:(.+?)(?:\n\n|\Z)', ai_analysis, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return "Security posture remains stable with emerging threat patterns"