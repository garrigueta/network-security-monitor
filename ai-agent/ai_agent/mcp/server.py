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
            "get_honeypot_activity": {
                "description": "Get recent honeypot activity and attack patterns",
                "parameters": {
                    "hours": {"type": "integer", "default": 24},
                    "limit": {"type": "integer", "default": 100}
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
            },
            "analyze_zeek_connections": {
                "description": "Analyze Zeek connection logs for network traffic patterns and anomalies",
                "parameters": {
                    "hours": {"type": "integer", "default": 24},
                    "min_bytes": {"type": "integer", "default": 0}
                }
            },
            "analyze_zeek_dns": {
                "description": "Analyze Zeek DNS logs for DNS query patterns and suspicious domains",
                "parameters": {
                    "hours": {"type": "integer", "default": 24}
                }
            },
            "analyze_zeek_http": {
                "description": "Analyze Zeek HTTP logs for web traffic patterns and potential attacks",
                "parameters": {
                    "hours": {"type": "integer", "default": 24}
                }
            },
            "analyze_zeek_files": {
                "description": "Analyze Zeek file logs for file transfers and types",
                "parameters": {
                    "hours": {"type": "integer", "default": 24}
                }
            },
            "get_zeek_logs": {
                "description": "Get raw Zeek logs of specific type from local filesystem",
                "parameters": {
                    "log_types": {"type": "array", "default": ["conn", "dns", "http"]},
                    "hours": {"type": "integer", "default": 24},
                    "limit": {"type": "integer", "default": 100}
                }
            }
        }
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, str]]:
        """Handle tool calls"""
        
        if name == "get_honeypot_activity":
            return await self._get_honeypot_activity(arguments)
        elif name == "get_network_metrics":
            return await self._get_network_metrics(arguments)
        elif name == "get_security_alerts":
            return await self._get_security_alerts(arguments)
        elif name == "analyze_threat_patterns":
            return await self._analyze_threat_patterns(arguments)
        elif name == "analyze_zeek_connections":
            return await self._analyze_zeek_connections(arguments)
        elif name == "analyze_zeek_dns":
            return await self._analyze_zeek_dns(arguments)
        elif name == "analyze_zeek_http":
            return await self._analyze_zeek_http(arguments)
        elif name == "analyze_zeek_files":
            return await self._analyze_zeek_files(arguments)
        elif name == "get_zeek_logs":
            return await self._get_zeek_logs(arguments)
        else:
            return [{"type": "text", "text": f"Unknown tool: {name}"}]
    
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
    
    async def _analyze_zeek_connections(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Analyze Zeek connection logs"""
        hours = args.get("hours", 24)
        min_bytes = args.get("min_bytes", 0)
        
        try:
            analysis = await self.data_collector.analyze_zeek_connections(hours=hours, min_bytes=min_bytes)
            
            if not analysis or analysis.get("total_connections", 0) == 0:
                return [{"type": "text", "text": "No Zeek connection data available."}]
            
            result_text = f"🔌 **Zeek Connection Analysis** (Last {hours}h):\n\n"
            
            result_text += f"📊 **Summary:**\n"
            result_text += f"• Total Connections: {analysis['total_connections']}\n"
            result_text += f"• Total Bytes Transferred: {analysis['bytes_transferred']['total'] / 1000000:.2f} MB\n"
            result_text += f"• Average Connection Duration: {analysis['duration_stats']['avg']:.2f}s\n\n"
            
            if analysis.get("protocols"):
                result_text += "🌐 **Protocols:**\n"
                for proto, count in list(analysis["protocols"].items())[:10]:
                    result_text += f"• {proto}: {count} connections\n"
                result_text += "\n"
            
            if analysis.get("services"):
                result_text += "🔧 **Services:**\n"
                for service, count in list(analysis["services"].items())[:10]:
                    if service != "unknown":
                        result_text += f"• {service}: {count} connections\n"
                result_text += "\n"
            
            if analysis.get("top_sources"):
                result_text += "📍 **Top Source IPs:**\n"
                for ip, count in list(analysis["top_sources"].items())[:5]:
                    result_text += f"• {ip}: {count} connections\n"
                result_text += "\n"
            
            if analysis.get("suspicious_patterns"):
                result_text += "⚠️ **Suspicious Patterns:**\n"
                for pattern in analysis["suspicious_patterns"][:10]:
                    result_text += f"• [{pattern['severity'].upper()}] {pattern['type']}: {pattern['description']}\n"
            
            return [{"type": "text", "text": result_text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error analyzing Zeek connections: {str(e)}"}]
    
    async def _analyze_zeek_dns(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Analyze Zeek DNS logs"""
        hours = args.get("hours", 24)
        
        try:
            analysis = await self.data_collector.analyze_zeek_dns(hours=hours)
            
            if not analysis or analysis.get("total_queries", 0) == 0:
                return [{"type": "text", "text": "No Zeek DNS data available."}]
            
            result_text = f"🔍 **Zeek DNS Analysis** (Last {hours}h):\n\n"
            
            result_text += f"📊 **Summary:**\n"
            result_text += f"• Total Queries: {analysis['total_queries']}\n\n"
            
            if analysis.get("query_types"):
                result_text += "📝 **Query Types:**\n"
                for qtype, count in list(analysis["query_types"].items())[:10]:
                    result_text += f"• {qtype}: {count}\n"
                result_text += "\n"
            
            if analysis.get("response_codes"):
                result_text += "📋 **Response Codes:**\n"
                for rcode, count in list(analysis["response_codes"].items())[:10]:
                    result_text += f"• {rcode}: {count}\n"
                result_text += "\n"
            
            if analysis.get("top_domains"):
                result_text += "🌐 **Top Queried Domains:**\n"
                for domain, count in list(analysis["top_domains"].items())[:10]:
                    result_text += f"• {domain}: {count} queries\n"
                result_text += "\n"
            
            if analysis.get("suspicious_domains"):
                result_text += "⚠️ **Suspicious Domains:**\n"
                for domain_info in analysis["suspicious_domains"][:10]:
                    result_text += f"• {domain_info['domain']} - {domain_info['reason']}\n"
            
            return [{"type": "text", "text": result_text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error analyzing Zeek DNS: {str(e)}"}]
    
    async def _analyze_zeek_http(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Analyze Zeek HTTP logs"""
        hours = args.get("hours", 24)
        
        try:
            analysis = await self.data_collector.analyze_zeek_http(hours=hours)
            
            if not analysis or analysis.get("total_requests", 0) == 0:
                return [{"type": "text", "text": "No Zeek HTTP data available."}]
            
            result_text = f"🌐 **Zeek HTTP Analysis** (Last {hours}h):\n\n"
            
            result_text += f"📊 **Summary:**\n"
            result_text += f"• Total Requests: {analysis['total_requests']}\n\n"
            
            if analysis.get("methods"):
                result_text += "📝 **HTTP Methods:**\n"
                for method, count in list(analysis["methods"].items()):
                    result_text += f"• {method}: {count}\n"
                result_text += "\n"
            
            if analysis.get("status_codes"):
                result_text += "📋 **Status Codes:**\n"
                for code, count in list(analysis["status_codes"].items())[:10]:
                    result_text += f"• {code}: {count}\n"
                result_text += "\n"
            
            if analysis.get("top_hosts"):
                result_text += "🏠 **Top Hosts:**\n"
                for host, count in list(analysis["top_hosts"].items())[:10]:
                    result_text += f"• {host}: {count} requests\n"
                result_text += "\n"
            
            if analysis.get("user_agents"):
                result_text += "🖥️ **Top User Agents:**\n"
                for ua, count in list(analysis["user_agents"].items())[:5]:
                    result_text += f"• {ua}: {count}\n"
                result_text += "\n"
            
            if analysis.get("suspicious_requests"):
                result_text += "⚠️ **Suspicious Requests:**\n"
                for req in analysis["suspicious_requests"][:10]:
                    result_text += f"• [{req['type']}] {req['method']} {req['host']}{req['uri']}\n"
            
            return [{"type": "text", "text": result_text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error analyzing Zeek HTTP: {str(e)}"}]
    
    async def _analyze_zeek_files(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Analyze Zeek file logs"""
        hours = args.get("hours", 24)
        
        try:
            analysis = await self.data_collector.analyze_zeek_files(hours=hours)
            
            if not analysis or analysis.get("total_files", 0) == 0:
                return [{"type": "text", "text": "No Zeek file data available."}]
            
            result_text = f"📁 **Zeek File Analysis** (Last {hours}h):\n\n"
            
            result_text += f"📊 **Summary:**\n"
            result_text += f"• Total Files: {analysis['total_files']}\n"
            result_text += f"• Total Size: {analysis['file_sizes']['total'] / 1000000:.2f} MB\n"
            result_text += f"• Average Size: {analysis['file_sizes']['avg'] / 1000:.2f} KB\n\n"
            
            if analysis.get("mime_types"):
                result_text += "📝 **MIME Types:**\n"
                for mime, count in list(analysis["mime_types"].items())[:10]:
                    result_text += f"• {mime}: {count}\n"
                result_text += "\n"
            
            if analysis.get("sources"):
                result_text += "🔧 **Sources:**\n"
                for source, count in list(analysis["sources"].items()):
                    result_text += f"• {source}: {count}\n"
                result_text += "\n"
            
            if analysis.get("large_files"):
                result_text += "📦 **Large Files (>10MB):**\n"
                for file_info in analysis["large_files"][:10]:
                    result_text += f"• {file_info['mime_type']}: {file_info['size_mb']:.2f} MB via {file_info['source']}\n"
                result_text += "\n"
            
            if analysis.get("executable_files"):
                result_text += "⚠️ **Executable Files:**\n"
                for exe_info in analysis["executable_files"][:10]:
                    result_text += f"• {exe_info['mime_type']} via {exe_info['source']}\n"
            
            return [{"type": "text", "text": result_text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error analyzing Zeek files: {str(e)}"}]
    
    async def _get_zeek_logs(self, args: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get raw Zeek logs"""
        log_types = args.get("log_types", ["conn", "dns", "http"])
        hours = args.get("hours", 24)
        limit = args.get("limit", 100)
        
        try:
            zeek_logs = await self.data_collector.get_local_zeek_logs(
                log_types=log_types,
                hours=hours,
                limit=limit
            )
            
            if not zeek_logs:
                return [{"type": "text", "text": "No Zeek logs available."}]
            
            result_text = f"📊 **Zeek Logs** (Last {hours}h, Limit: {limit}):\n\n"
            
            for log_type, logs in zeek_logs.items():
                result_text += f"\n**{log_type.upper()} logs:** {len(logs)} entries\n"
                
                # Show first few entries as examples
                for i, log in enumerate(logs[:3]):
                    result_text += f"\nEntry {i+1}:\n"
                    # Show key fields only
                    important_fields = ['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 
                                       'proto', 'service', 'query', 'host', 'uri', 'method']
                    for field in important_fields:
                        if field in log and log[field] is not None:
                            result_text += f"  {field}: {log[field]}\n"
            
            return [{"type": "text", "text": result_text}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error getting Zeek logs: {str(e)}"}]


# Global MCP server instance
mcp_server = NetworkSecurityMCPServer()