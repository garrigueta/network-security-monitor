"""MCP Server for Network Security Data Access"""

import asyncio
import json
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import httpx

from ..config import settings
from ..data_sources import DataCollector


class NetworkSecurityMCPServer:
    """MCP Server providing structured access to network security data"""
    
    def __init__(self):
        self.data_collector = DataCollector()
        self.tools = self._setup_tools()
    
    def _setup_tools(self):
        """Setup available MCP tools"""
        return {
            "get_all_logs": {
                "description": "Get comprehensive logs from all sources (honeypots, Zeek, Loki)",
                "parameters": {
                    "hours": {"type": "integer", "default": 24},
                    "include_files": {"type": "boolean", "default": False}
                }
            },
            "get_honeypot_activity": {
                "description": "Get recent honeypot activity and attack patterns",
                "parameters": {
                    "hours": {"type": "integer", "default": 24},
                    "limit": {"type": "integer", "default": 100}
                }
            },
            "get_zeek_logs": {
                "description": "Get Zeek network monitoring logs by type",
                "parameters": {
                    "log_type": {"type": "string", "optional": True},
                    "hours": {"type": "integer", "default": 24}
                }
            },
            "get_network_metrics": {
                "description": "Get network and system metrics",
                "parameters": {
                    "metric": {"type": "string", "required": True},
                    "duration": {"type": "string", "default": "1h"}
                }
            },
            "get_security_alerts": {
                "description": "Get security alerts and anomalies",
                "parameters": {
                    "severity": {"type": "string", "default": "all"},
                    "source": {"type": "string", "default": "all"}
                }
            },
            "analyze_threat_patterns": {
                "description": "Analyze threat patterns and attack vectors",
                "parameters": {
                    "timeframe": {"type": "string", "default": "24h"},
                    "focus": {"type": "string", "default": "all"}
                }
            }
        }
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, str]]:
        """Handle tool calls"""
        
        if name == "get_all_logs":
            return await self._get_all_logs(arguments)
        elif name == "get_honeypot_activity":
            return await self._get_honeypot_activity(arguments)
        elif name == "get_zeek_logs":
            return await self._get_zeek_logs(arguments)
        elif name == "get_network_metrics":
            return await self._get_network_metrics(arguments)
        elif name == "get_security_alerts":
            return await self._get_security_alerts(arguments)
        elif name == "analyze_threat_patterns":
            return await self._analyze_threat_patterns(arguments)
        else:
            return [{"type": "text", "text": f"Unknown tool: {name}"}]
    
    async def _get_all_logs(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get comprehensive logs from all sources"""
        hours = args.get("hours", 24)
        include_files = args.get("include_files", False)
        
        try:
            all_logs = await self.data_collector.get_all_logs(
                hours=hours,
                include_raw_files=include_files
            )
            
            summary = all_logs["summary"]
            sources = all_logs["sources"]
            
            text = f"📊 **Comprehensive Log Analysis** (Last {hours}h):\n\n"
            text += f"**Total Events:** {summary['total_entries']}\n\n"
            text += "**Breakdown by Source:**\n"
            
            for source, count in summary["by_source"].items():
                text += f"• {source}: {count:,} events\n"
            
            text += "\n**Honeypot Activity:**\n"
            text += f"• Cowrie events: {len(sources['honeypot'].get('cowrie', []))}\n"
            text += f"• Heralding events: {len(sources['honeypot'].get('heralding', []))}\n"
            
            text += "\n**Zeek Network Logs:**\n"
            zeek_logs = sources.get("zeek", {})
            for log_type, entries in zeek_logs.items():
                if entries:
                    text += f"• {log_type}: {len(entries)} entries\n"
            
            text += "\n**Loki Aggregation:**\n"
            text += f"• Honeypot entries: {len(sources['loki'].get('honeypot_entries', []))}\n"
            text += f"• Zeek entries: {len(sources['loki'].get('zeek_entries', []))}\n"
            
            if include_files:
                text += "\n**File Paths Available:**\n"
                file_paths = all_logs.get("file_paths", {})
                text += f"• Honeypot files: {len(file_paths.get('honeypot', {}).get('cowrie', []))} + {len(file_paths.get('honeypot', {}).get('heralding', []))}\n"
                text += f"• Zeek log files: {len(file_paths.get('zeek', []))}\n"
            
            return [{"type": "text", "text": text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error getting all logs: {str(e)}"}]
    
    async def _get_zeek_logs(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get Zeek network monitoring logs"""
        log_type = args.get("log_type")
        hours = args.get("hours", 24)
        
        try:
            if log_type:
                zeek_logs = await self.data_collector.get_local_zeek_logs(
                    log_types=[log_type],
                    hours=hours
                )
            else:
                zeek_logs = await self.data_collector.get_local_zeek_logs(hours=hours)
            
            text = f"🔍 **Zeek Logs** "
            if log_type:
                text += f"({log_type}) "
            text += f"(Last {hours}h):\n\n"
            
            total_entries = sum(len(entries) for entries in zeek_logs.values())
            text += f"**Total Entries:** {total_entries:,}\n\n"
            text += "**Log Types:**\n"
            
            for ltype, entries in zeek_logs.items():
                text += f"• {ltype}: {len(entries):,} entries\n"
            
            return [{"type": "text", "text": text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error getting Zeek logs: {str(e)}"}]
    
    async def _get_honeypot_activity(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get honeypot activity data"""
        hours = args.get("hours", 24)
        limit = args.get("limit", 100)
        
        try:
            data = await self.data_collector.get_honeypot_logs(hours=hours, limit=limit)
            
            # Analyze the data
            analysis = {
                "total_events": len(data),
                "unique_ips": len(set(event.get("src_ip", "") for event in data)),
                "event_types": {},
                "top_ips": {},
                "recent_events": data[:10]  # Last 10 events
            }
            
            # Count event types
            for event in data:
                event_type = event.get("eventid", "unknown")
                analysis["event_types"][event_type] = analysis["event_types"].get(event_type, 0) + 1
            
            # Count top IPs
            for event in data:
                ip = event.get("src_ip", "unknown")
                analysis["top_ips"][ip] = analysis["top_ips"].get(ip, 0) + 1
            
            # Sort top IPs
            analysis["top_ips"] = dict(sorted(analysis["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10])
            
            return [{"type": "text", "text": 
                f"Honeypot Activity Analysis (Last {hours}h):\n\n" +
                f"📊 **Summary:**\n" +
                f"• Total Events: {analysis['total_events']}\n" +
                f"• Unique Source IPs: {analysis['unique_ips']}\n\n" +
                f"🎯 **Event Types:**\n" +
                "\n".join(f"• {etype}: {count}" for etype, count in analysis["event_types"].items()) +
                f"\n\n🌐 **Top Source IPs:**\n" +
                "\n".join(f"• {ip}: {count} events" for ip, count in analysis["top_ips"].items()) +
                f"\n\n📝 **Recent Events:**\n" +
                "\n".join(f"• {event.get('timestamp', 'N/A')} - {event.get('src_ip', 'N/A')} - {event.get('eventid', 'N/A')}" 
                          for event in analysis["recent_events"][:5])
            }]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error getting honeypot activity: {str(e)}"}]
    
    async def _get_network_metrics(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get network metrics from Prometheus"""
        metric = args.get("metric")
        duration = args.get("duration", "1h")
        
        try:
            data = await self.data_collector.get_prometheus_metrics(metric, duration)
            
            return [{"type": "text", "text": 
                f"Network Metrics - {metric} (Last {duration}):\n\n" +
                json.dumps(data, indent=2)
            }]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error getting network metrics: {str(e)}"}]
    
    async def _get_security_alerts(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get security alerts and anomalies"""
        severity = args.get("severity", "all")
        source = args.get("source", "all")
        
        try:
            alerts = await self.data_collector.get_security_alerts(severity, source)
            
            if not alerts:
                return [{"type": "text", "text": "No security alerts found."}]
            
            alert_text = f"🚨 **Security Alerts** (Severity: {severity}, Source: {source}):\n\n"
            
            for alert in alerts[:10]:  # Show top 10 alerts
                alert_text += f"• **{alert.get('severity', 'UNKNOWN').upper()}** - "
                alert_text += f"{alert.get('title', 'No title')} "
                alert_text += f"({alert.get('source', 'unknown')})\n"
                alert_text += f"  Time: {alert.get('timestamp', 'N/A')}\n"
                alert_text += f"  Details: {alert.get('description', 'No details')}\n\n"
            
            return [{"type": "text", "text": alert_text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error getting security alerts: {str(e)}"}]
    
    async def _analyze_threat_patterns(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Analyze threat patterns and attack vectors"""
        timeframe = args.get("timeframe", "24h")
        focus = args.get("focus", "all")
        
        try:
            patterns = await self.data_collector.analyze_threats(timeframe, focus)
            
            analysis_text = f"🔍 **Threat Pattern Analysis** (Last {timeframe}, Focus: {focus}):\n\n"
            
            if patterns.get("attack_vectors"):
                analysis_text += "🎯 **Attack Vectors:**\n"
                for vector, count in patterns["attack_vectors"].items():
                    analysis_text += f"• {vector}: {count} attempts\n"
                analysis_text += "\n"
            
            if patterns.get("geographic_distribution"):
                analysis_text += "🌍 **Geographic Distribution:**\n"
                for country, count in patterns["geographic_distribution"].items():
                    analysis_text += f"• {country}: {count} attacks\n"
                analysis_text += "\n"
            
            if patterns.get("temporal_patterns"):
                analysis_text += "⏰ **Temporal Patterns:**\n"
                analysis_text += f"• Peak activity hour: {patterns['temporal_patterns'].get('peak_hour', 'N/A')}\n"
                analysis_text += f"• Attack frequency trend: {patterns['temporal_patterns'].get('trend', 'N/A')}\n\n"
            
            if patterns.get("recommendations"):
                analysis_text += "💡 **Recommendations:**\n"
                for rec in patterns["recommendations"]:
                    analysis_text += f"• {rec}\n"
            
            return [{"type": "text", "text": analysis_text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error analyzing threat patterns: {str(e)}"}]


# Global MCP server instance
mcp_server = NetworkSecurityMCPServer()