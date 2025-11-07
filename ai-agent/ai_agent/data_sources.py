"""Data collection from various monitoring sources"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import httpx
import structlog

from .config import settings

logger = structlog.get_logger()

# Constants for threat detection thresholds
SUSPICIOUS_DURATION_THRESHOLD_SECONDS = 3600  # 1 hour
LARGE_DATA_TRANSFER_BYTES = 100000000  # 100 MB
LARGE_FILE_THRESHOLD_BYTES = 10000000  # 10 MB


class DataCollector:
    """Collects data from various monitoring infrastructure components"""
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=30.0)
    
    async def get_honeypot_logs(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get honeypot logs from Loki or local filesystem"""
        logs = []
        
        try:
            # Try reading from local filesystem first
            local_logs = await self.get_local_honeypot_logs(hours)
            if local_logs:
                logger.info(f"Retrieved {len(local_logs)} honeypot logs from local filesystem")
                logs.extend(local_logs)
        except Exception as e:
            logger.warning(f"Could not read local honeypot logs: {e}")
        
        # Also try Loki as secondary source
        try:
            # Calculate time range
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            
            # Convert to nanoseconds (Loki format)
            start_ns = int(start_time.timestamp() * 1_000_000_000)
            end_ns = int(end_time.timestamp() * 1_000_000_000)
            
            # Query Loki for honeypot logs
            query = '{job="honeypot"} | json'
            url = f"{settings.loki_url}/loki/api/v1/query_range"
            
            params = {
                "query": query,
                "start": start_ns,
                "end": end_ns,
                "limit": limit,
                "direction": "backward"
            }
            
            response = await self.http_client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "success" and data.get("data", {}).get("result"):
                for stream in data["data"]["result"]:
                    for entry in stream.get("values", []):
                        timestamp, log_line = entry
                        try:
                            # Try to parse as JSON
                            log_data = json.loads(log_line)
                            log_data["timestamp"] = timestamp
                            logs.append(log_data)
                        except json.JSONDecodeError:
                            # Fallback for non-JSON logs
                            logs.append({
                                "timestamp": timestamp,
                                "message": log_line,
                                "raw": True
                            })
                
                logger.info(f"Retrieved {len(data['data']['result'])} additional honeypot log entries from Loki")
            
        except Exception as e:
            logger.warning(f"Error fetching honeypot logs from Loki: {e}")
        
        logger.info(f"Total honeypot logs retrieved: {len(logs)}")
        return logs[:limit] if limit else logs
    
    async def get_prometheus_metrics(self, metric: str, duration: str = "1h") -> Dict[str, Any]:
        """Get metrics from Prometheus"""
        try:
            # Map metric names to Prometheus queries
            metric_queries = {
                "cpu_usage": 'rate(node_cpu_seconds_total{mode!="idle"}[5m])',
                "memory_usage": 'node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes',
                "network_connections": 'node_netstat_Tcp_CurrEstab',
                "disk_io": 'rate(node_disk_io_time_seconds_total[5m])'
            }
            
            query = metric_queries.get(metric, metric)
            url = f"{settings.prometheus_url}/api/v1/query"
            
            params = {"query": query}
            
            response = await self.http_client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "success":
                return data.get("data", {})
            else:
                logger.error(f"Prometheus query failed: {data}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching Prometheus metrics: {e}")
            return {}
    
    async def get_security_alerts(self, severity: str = "all", source: str = "all") -> List[Dict[str, Any]]:
        """Get security alerts from various sources"""
        alerts = []
        
        try:
            # Get honeypot-based alerts
            if source in ["honeypot", "all"]:
                honeypot_alerts = await self._analyze_honeypot_alerts(severity)
                alerts.extend(honeypot_alerts)
            
            # Get system-based alerts from Prometheus
            if source in ["prometheus", "all"]:
                system_alerts = await self._analyze_system_alerts(severity)
                alerts.extend(system_alerts)
            
            # Get Zeek-based alerts
            if source in ["zeek", "all"]:
                zeek_alerts = await self._analyze_zeek_alerts(severity)
                alerts.extend(zeek_alerts)
            
            # Sort by timestamp (most recent first)
            alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            logger.info(f"Retrieved {len(alerts)} security alerts")
            return alerts
            
        except Exception as e:
            logger.error(f"Error fetching security alerts: {e}")
            return []
    
    async def _analyze_honeypot_alerts(self, severity: str) -> List[Dict[str, Any]]:
        """Analyze honeypot logs for security alerts"""
        alerts = []
        
        try:
            # Get recent honeypot logs
            logs = await self.get_honeypot_logs(hours=1, limit=100)
            
            # Analyze for suspicious patterns
            ip_counts = {}
            for log in logs:
                src_ip = log.get("src_ip")
                if src_ip:
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
            
            # Generate alerts for high-activity IPs
            for ip, count in ip_counts.items():
                if count > 10:  # Threshold for suspicious activity
                    alert_severity = "high" if count > 50 else "medium" if count > 20 else "low"
                    
                    if severity == "all" or severity == alert_severity:
                        alerts.append({
                            "severity": alert_severity,
                            "title": f"High Activity from IP {ip}",
                            "description": f"IP {ip} generated {count} honeypot events in the last hour",
                            "source": "honeypot",
                            "timestamp": datetime.now().isoformat(),
                            "details": {"ip": ip, "event_count": count}
                        })
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error analyzing honeypot alerts: {e}")
            return []
    
    async def _analyze_system_alerts(self, severity: str) -> List[Dict[str, Any]]:
        """Analyze system metrics for alerts"""
        alerts = []
        
        try:
            # Check CPU usage
            cpu_data = await self.get_prometheus_metrics("cpu_usage")
            if cpu_data.get("result"):
                for result in cpu_data["result"]:
                    value = float(result["value"][1])
                    if value > 0.9:  # 90% CPU usage
                        alerts.append({
                            "severity": "high" if value > 0.95 else "medium",
                            "title": "High CPU Usage",
                            "description": f"CPU usage is at {value*100:.1f}%",
                            "source": "prometheus",
                            "timestamp": datetime.now().isoformat(),
                            "details": {"cpu_usage": value}
                        })
            
            # Check memory usage
            mem_data = await self.get_prometheus_metrics("memory_usage")
            if mem_data.get("result"):
                for result in mem_data["result"]:
                    available_ratio = float(result["value"][1])
                    used_ratio = 1 - available_ratio
                    if used_ratio > 0.9:  # 90% memory usage
                        alerts.append({
                            "severity": "high" if used_ratio > 0.95 else "medium",
                            "title": "High Memory Usage",
                            "description": f"Memory usage is at {used_ratio*100:.1f}%",
                            "source": "prometheus",
                            "timestamp": datetime.now().isoformat(),
                            "details": {"memory_usage": used_ratio}
                        })
            
            return [alert for alert in alerts if severity == "all" or alert["severity"] == severity]
            
        except Exception as e:
            logger.error(f"Error analyzing system alerts: {e}")
            return []
    
    async def _analyze_zeek_alerts(self, severity: str) -> List[Dict[str, Any]]:
        """Analyze Zeek logs for security alerts"""
        alerts = []
        
        try:
            # Query Zeek logs from Loki
            query = '{job="zeek"}'
            url = f"{settings.loki_url}/loki/api/v1/query_range"
            
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            
            params = {
                "query": query,
                "start": int(start_time.timestamp() * 1_000_000_000),
                "end": int(end_time.timestamp() * 1_000_000_000),
                "limit": 100
            }
            
            response = await self.http_client.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                
                # Analyze Zeek logs for suspicious patterns
                # This is a simplified example - you can expand based on Zeek log types
                log_count = 0
                if data.get("data", {}).get("result"):
                    for stream in data["data"]["result"]:
                        log_count += len(stream.get("values", []))
                
                if log_count > 1000:  # High network activity
                    alerts.append({
                        "severity": "medium",
                        "title": "High Network Activity",
                        "description": f"Zeek recorded {log_count} network events in the last hour",
                        "source": "zeek",
                        "timestamp": datetime.now().isoformat(),
                        "details": {"event_count": log_count}
                    })
            
            return [alert for alert in alerts if severity == "all" or alert["severity"] == severity]
            
        except Exception as e:
            logger.error(f"Error analyzing Zeek alerts: {e}")
            return []
    
    async def analyze_threats(self, timeframe: str = "24h", focus: str = "all") -> Dict[str, Any]:
        """Analyze threat patterns across timeframe"""
        try:
            # Convert timeframe to hours
            timeframe_hours = {
                "1h": 1,
                "6h": 6,
                "24h": 24,
                "7d": 168
            }.get(timeframe, 24)
            
            # Get honeypot data for analysis
            logs = await self.get_honeypot_logs(hours=timeframe_hours, limit=1000)
            
            analysis = {
                "attack_vectors": {},
                "geographic_distribution": {},
                "temporal_patterns": {},
                "recommendations": []
            }
            
            if not logs:
                return analysis
            
            # Analyze attack vectors
            for log in logs:
                event_type = log.get("eventid", "unknown")
                analysis["attack_vectors"][event_type] = analysis["attack_vectors"].get(event_type, 0) + 1
            
            # Sort attack vectors by frequency
            analysis["attack_vectors"] = dict(sorted(analysis["attack_vectors"].items(), key=lambda x: x[1], reverse=True))
            
            # Analyze geographic distribution (simplified - you could use GeoIP)
            ip_countries = {}
            for log in logs:
                src_ip = log.get("src_ip", "")
                if src_ip:
                    # Simplified country detection based on IP ranges
                    country = self._get_country_from_ip(src_ip)
                    ip_countries[country] = ip_countries.get(country, 0) + 1
            
            analysis["geographic_distribution"] = dict(sorted(ip_countries.items(), key=lambda x: x[1], reverse=True)[:10])
            
            # Temporal pattern analysis
            hourly_counts = {}
            for log in logs:
                timestamp = log.get("timestamp", "")
                if timestamp:
                    try:
                        # Parse timestamp and extract hour
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        hour = dt.hour
                        hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
                    except:
                        continue
            
            if hourly_counts:
                peak_hour = max(hourly_counts.items(), key=lambda x: x[1])[0]
                analysis["temporal_patterns"]["peak_hour"] = f"{peak_hour:02d}:00"
                
                # Simple trend analysis
                total_events = sum(hourly_counts.values())
                recent_events = sum(hourly_counts.get(h, 0) for h in range(max(0, datetime.now().hour - 6), datetime.now().hour + 1))
                if recent_events > total_events * 0.3:
                    analysis["temporal_patterns"]["trend"] = "increasing"
                else:
                    analysis["temporal_patterns"]["trend"] = "stable"
            
            # Generate recommendations
            top_attack = max(analysis["attack_vectors"].items(), key=lambda x: x[1])[0] if analysis["attack_vectors"] else None
            if top_attack:
                analysis["recommendations"].append(f"Monitor and enhance defenses against {top_attack} attacks")
            
            if len(analysis["geographic_distribution"]) > 5:
                analysis["recommendations"].append("Consider implementing geo-blocking for countries with high attack frequency")
            
            total_events = len(logs)
            if total_events > 500:
                analysis["recommendations"].append("High attack volume detected - consider reviewing honeypot exposure")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing threats: {e}")
            return {}
    
    def _get_country_from_ip(self, ip: str) -> str:
        """Simplified country detection from IP (replace with proper GeoIP)"""
        # This is a very simplified example - use a proper GeoIP service in production
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Local"
        elif ip.startswith("185."):
            return "Europe"
        elif ip.startswith("134."):
            return "Asia"
        else:
            return "Unknown"
    
    async def get_local_honeypot_logs(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Read honeypot logs directly from local filesystem"""
        logs = []
        
        try:
            import os
            import csv
            from pathlib import Path
            
            honeypot_base = Path("/mnt/honeypot-logs")
            
            # Read Cowrie JSON logs
            cowrie_log = honeypot_base / "cowrie" / "cowrie.json"
            if cowrie_log.exists():
                logger.info(f"Reading Cowrie logs from {cowrie_log}")
                with open(cowrie_log, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            log_entry["source"] = "cowrie"
                            logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
            
            # Read Heralding CSV logs
            heralding_auth = honeypot_base / "heralding" / "log_auth.csv"
            if heralding_auth.exists():
                logger.info(f"Reading Heralding auth logs from {heralding_auth}")
                with open(heralding_auth, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row["source"] = "heralding"
                        row["type"] = "auth"
                        logs.append(row)
            
            # Read Heralding session logs
            heralding_session = honeypot_base / "heralding" / "log_session.csv"
            if heralding_session.exists():
                logger.info(f"Reading Heralding session logs from {heralding_session}")
                with open(heralding_session, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row["source"] = "heralding"
                        row["type"] = "session"
                        logs.append(row)
            
            # Read Heralding JSON logs
            heralding_json = honeypot_base / "heralding" / "log_session.json"
            if heralding_json.exists() and os.path.getsize(heralding_json) > 0:
                logger.info(f"Reading Heralding JSON logs from {heralding_json}")
                with open(heralding_json, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            log_entry["source"] = "heralding"
                            logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
            
            logger.info(f"Retrieved {len(logs)} honeypot log entries from local filesystem")
            return logs
            
        except Exception as e:
            logger.error(f"Error reading local honeypot logs: {e}")
            return []
    
    async def get_local_zeek_logs(self, log_types: List[str] = None, hours: int = 24, limit: int = 1000) -> Dict[str, List[Dict[str, Any]]]:
        """Read Zeek logs directly from local filesystem with proper field mapping"""
        zeek_logs = {}
        
        try:
            from pathlib import Path
            from datetime import datetime, timedelta
            
            if log_types is None:
                # Expanded list of important Zeek log types
                log_types = ["conn", "dns", "http", "ssl", "ssh", "files", "weird", "notice", "software", "x509", "pe"]
            
            zeek_base = Path("/mnt/zeek-logs/logs/current")
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            for log_type in log_types:
                log_file = zeek_base / f"{log_type}.log"
                if log_file.exists():
                    logger.info(f"Reading Zeek {log_type} logs from {log_file}")
                    entries = []
                    field_names = []
                    field_types = []
                    
                    with open(log_file, 'r') as f:
                        for line in f:
                            # Parse header comments to get field names and types
                            if line.startswith('#fields'):
                                field_names = line.strip().split('\t')[1:]  # Skip '#fields' part
                            elif line.startswith('#types'):
                                field_types = line.strip().split('\t')[1:]  # Skip '#types' part
                            elif line.startswith('#') or not line.strip():
                                continue  # Skip other comments and empty lines
                            else:
                                # Parse data line
                                try:
                                    values = line.strip().split('\t')
                                    
                                    # Create structured entry with field mapping
                                    if field_names and len(values) == len(field_names):
                                        entry = {
                                            "log_type": log_type,
                                            "source": "zeek"
                                        }
                                        
                                        for i, field_name in enumerate(field_names):
                                            value = values[i]
                                            # Convert Zeek's unset values
                                            if value == '-':
                                                entry[field_name] = None
                                            else:
                                                # Type conversion based on Zeek types if available
                                                if field_types and i < len(field_types):
                                                    entry[field_name] = self._convert_zeek_value(value, field_types[i])
                                                else:
                                                    entry[field_name] = value
                                        
                                        # Filter by timestamp if 'ts' field exists
                                        if 'ts' in entry and entry['ts'] is not None:
                                            try:
                                                log_time = datetime.fromtimestamp(float(entry['ts']))
                                                if log_time < cutoff_time:
                                                    continue
                                            except (ValueError, TypeError):
                                                pass
                                        
                                        entries.append(entry)
                                        
                                        # Respect limit
                                        if len(entries) >= limit:
                                            break
                                    else:
                                        # Fallback for logs without proper header
                                        entry = {
                                            "raw": line.strip(),
                                            "log_type": log_type,
                                            "source": "zeek"
                                        }
                                        entries.append(entry)
                                        
                                except Exception as e:
                                    logger.debug(f"Error parsing Zeek line: {e}")
                                    continue
                    
                    zeek_logs[log_type] = entries
                    logger.info(f"Retrieved {len(entries)} entries from {log_type}.log")
            
            return zeek_logs
            
        except Exception as e:
            logger.error(f"Error reading local Zeek logs: {e}")
            return {}
    
    def _convert_zeek_value(self, value: str, zeek_type: str) -> Any:
        """Convert Zeek value based on its type"""
        try:
            if zeek_type in ['count', 'port']:
                return int(value)
            elif zeek_type in ['time', 'interval', 'double']:
                return float(value)
            elif zeek_type == 'bool':
                return value.upper() == 'T'
            elif zeek_type.startswith('vector') or zeek_type.startswith('set'):
                # Handle vector and set types (comma-separated)
                if value == '(empty)':
                    return []
                return value.split(',')
            else:
                # String types and others
                return value
        except (ValueError, AttributeError):
            return value
    
    async def get_zeek_logs_from_loki(self, log_type: str = "all", hours: int = 24, limit: int = 100, filters: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """Get Zeek logs from Loki with advanced filtering"""
        logs = []
        
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            
            # Convert to nanoseconds (Loki format)
            start_ns = int(start_time.timestamp() * 1_000_000_000)
            end_ns = int(end_time.timestamp() * 1_000_000_000)
            
            # Build Loki query with filters
            if log_type == "all":
                query = '{job="zeek"}'
            else:
                query = f'{{job="zeek", log_type="{log_type}"}}'
            
            # Add LogQL filters if provided
            if filters:
                filter_expressions = []
                for key, value in filters.items():
                    filter_expressions.append(f'{key}=~"{value}"')
                if filter_expressions:
                    query += f' | json | {" | ".join(filter_expressions)}'
            else:
                query += ' | json'
            
            url = f"{settings.loki_url}/loki/api/v1/query_range"
            
            params = {
                "query": query,
                "start": start_ns,
                "end": end_ns,
                "limit": limit,
                "direction": "backward"
            }
            
            response = await self.http_client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "success" and data.get("data", {}).get("result"):
                for stream in data["data"]["result"]:
                    for entry in stream.get("values", []):
                        timestamp, log_line = entry
                        try:
                            log_data = json.loads(log_line)
                            log_data["timestamp"] = timestamp
                            logs.append(log_data)
                        except json.JSONDecodeError:
                            logs.append({
                                "timestamp": timestamp,
                                "message": log_line,
                                "raw": True
                            })
                
                logger.info(f"Retrieved {len(logs)} Zeek {log_type} log entries from Loki")
            
        except Exception as e:
            logger.warning(f"Error fetching Zeek logs from Loki: {e}")
        
        return logs
    
    async def analyze_zeek_connections(self, hours: int = 24, min_bytes: int = 0) -> Dict[str, Any]:
        """Analyze Zeek connection logs for patterns and anomalies"""
        try:
            # Get connection logs
            zeek_logs = await self.get_local_zeek_logs(log_types=["conn"], hours=hours, limit=5000)
            conn_logs = zeek_logs.get("conn", [])
            
            analysis = {
                "total_connections": len(conn_logs),
                "protocols": {},
                "services": {},
                "top_sources": {},
                "top_destinations": {},
                "duration_stats": {"min": 0, "max": 0, "avg": 0},
                "bytes_transferred": {"total": 0, "avg": 0},
                "connection_states": {},
                "suspicious_patterns": []
            }
            
            if not conn_logs:
                return analysis
            
            durations = []
            bytes_total = []
            
            for log in conn_logs:
                # Protocol analysis
                proto = log.get("proto", "unknown")
                analysis["protocols"][proto] = analysis["protocols"].get(proto, 0) + 1
                
                # Service analysis
                service = log.get("service", "unknown")
                if service:
                    analysis["services"][service] = analysis["services"].get(service, 0) + 1
                
                # Source IP analysis
                src_ip = log.get("id.orig_h", "unknown")
                analysis["top_sources"][src_ip] = analysis["top_sources"].get(src_ip, 0) + 1
                
                # Destination IP analysis
                dst_ip = log.get("id.resp_h", "unknown")
                analysis["top_destinations"][dst_ip] = analysis["top_destinations"].get(dst_ip, 0) + 1
                
                # Duration stats
                duration = log.get("duration")
                if duration is not None and isinstance(duration, (int, float)):
                    durations.append(duration)
                
                # Bytes transferred
                orig_bytes = log.get("orig_bytes", 0) or 0
                resp_bytes = log.get("resp_bytes", 0) or 0
                total_bytes = 0
                if isinstance(orig_bytes, (int, float)) and isinstance(resp_bytes, (int, float)):
                    total_bytes = orig_bytes + resp_bytes
                    bytes_total.append(total_bytes)
                
                # Connection state
                conn_state = log.get("conn_state", "unknown")
                analysis["connection_states"][conn_state] = analysis["connection_states"].get(conn_state, 0) + 1
                
                # Detect suspicious patterns
                # Long duration connections (> 1 hour)
                if duration and duration > SUSPICIOUS_DURATION_THRESHOLD_SECONDS:
                    analysis["suspicious_patterns"].append({
                        "type": "long_duration",
                        "description": f"Connection from {src_ip} to {dst_ip} lasted {duration:.1f}s",
                        "severity": "medium"
                    })
                
                # High data transfer
                if total_bytes > LARGE_DATA_TRANSFER_BYTES:  # > 100MB
                    analysis["suspicious_patterns"].append({
                        "type": "high_data_transfer",
                        "description": f"Large data transfer ({total_bytes/1000000:.1f}MB) from {src_ip} to {dst_ip}",
                        "severity": "medium"
                    })
            
            # Calculate stats
            if durations:
                analysis["duration_stats"]["min"] = min(durations)
                analysis["duration_stats"]["max"] = max(durations)
                analysis["duration_stats"]["avg"] = sum(durations) / len(durations)
            
            if bytes_total:
                analysis["bytes_transferred"]["total"] = sum(bytes_total)
                analysis["bytes_transferred"]["avg"] = sum(bytes_total) / len(bytes_total)
            
            # Sort top sources and destinations
            analysis["top_sources"] = dict(sorted(analysis["top_sources"].items(), key=lambda x: x[1], reverse=True)[:10])
            analysis["top_destinations"] = dict(sorted(analysis["top_destinations"].items(), key=lambda x: x[1], reverse=True)[:10])
            
            # Limit suspicious patterns
            analysis["suspicious_patterns"] = analysis["suspicious_patterns"][:20]
            
            logger.info(f"Analyzed {len(conn_logs)} Zeek connection logs")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing Zeek connections: {e}")
            return {}
    
    async def analyze_zeek_dns(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze Zeek DNS logs for patterns and anomalies"""
        try:
            zeek_logs = await self.get_local_zeek_logs(log_types=["dns"], hours=hours, limit=5000)
            dns_logs = zeek_logs.get("dns", [])
            
            analysis = {
                "total_queries": len(dns_logs),
                "query_types": {},
                "top_domains": {},
                "response_codes": {},
                "failed_queries": [],
                "suspicious_domains": []
            }
            
            if not dns_logs:
                return analysis
            
            for log in dns_logs:
                # Query type analysis
                qtype_name = log.get("qtype_name", "unknown")
                analysis["query_types"][qtype_name] = analysis["query_types"].get(qtype_name, 0) + 1
                
                # Domain analysis
                query = log.get("query", "")
                if query:
                    analysis["top_domains"][query] = analysis["top_domains"].get(query, 0) + 1
                
                # Response code analysis
                rcode_name = log.get("rcode_name", "unknown")
                analysis["response_codes"][rcode_name] = analysis["response_codes"].get(rcode_name, 0) + 1
                
                # Failed queries
                if rcode_name and rcode_name != "NOERROR":
                    analysis["failed_queries"].append({
                        "query": query,
                        "rcode": rcode_name,
                        "timestamp": log.get("ts")
                    })
                
                # Suspicious domain patterns
                if query:
                    # Check for unusual patterns (very long domain, many subdomains, etc.)
                    if len(query) > 50:
                        analysis["suspicious_domains"].append({
                            "domain": query,
                            "reason": "unusually_long",
                            "length": len(query)
                        })
                    elif query.count('.') > 5:
                        analysis["suspicious_domains"].append({
                            "domain": query,
                            "reason": "many_subdomains",
                            "subdomain_count": query.count('.')
                        })
            
            # Sort and limit
            analysis["top_domains"] = dict(sorted(analysis["top_domains"].items(), key=lambda x: x[1], reverse=True)[:20])
            analysis["failed_queries"] = analysis["failed_queries"][:20]
            analysis["suspicious_domains"] = analysis["suspicious_domains"][:20]
            
            logger.info(f"Analyzed {len(dns_logs)} Zeek DNS logs")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing Zeek DNS: {e}")
            return {}
    
    async def analyze_zeek_http(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze Zeek HTTP logs for web traffic patterns"""
        try:
            zeek_logs = await self.get_local_zeek_logs(log_types=["http"], hours=hours, limit=5000)
            http_logs = zeek_logs.get("http", [])
            
            analysis = {
                "total_requests": len(http_logs),
                "methods": {},
                "status_codes": {},
                "user_agents": {},
                "top_hosts": {},
                "top_uris": {},
                "file_downloads": [],
                "suspicious_requests": []
            }
            
            if not http_logs:
                return analysis
            
            for log in http_logs:
                # HTTP method analysis
                method = log.get("method", "unknown")
                analysis["methods"][method] = analysis["methods"].get(method, 0) + 1
                
                # Status code analysis
                status_code = log.get("status_code")
                if status_code:
                    analysis["status_codes"][str(status_code)] = analysis["status_codes"].get(str(status_code), 0) + 1
                
                # User agent analysis
                user_agent = log.get("user_agent", "")
                if user_agent and user_agent != "-":
                    # Truncate long user agents for display
                    ua_short = user_agent[:50] + "..." if len(user_agent) > 50 else user_agent
                    analysis["user_agents"][ua_short] = analysis["user_agents"].get(ua_short, 0) + 1
                
                # Host analysis
                host = log.get("host", "")
                if host:
                    analysis["top_hosts"][host] = analysis["top_hosts"].get(host, 0) + 1
                
                # URI analysis
                uri = log.get("uri", "")
                if uri and len(uri) < 100:  # Only track reasonable URIs
                    analysis["top_uris"][uri] = analysis["top_uris"].get(uri, 0) + 1
                
                # File downloads (based on response MIME types)
                resp_mime_types = log.get("resp_mime_types", [])
                if resp_mime_types and isinstance(resp_mime_types, list):
                    for mime_type in resp_mime_types:
                        if any(t in mime_type for t in ["application/", "image/", "video/", "audio/"]):
                            analysis["file_downloads"].append({
                                "host": host,
                                "uri": uri[:100],
                                "mime_type": mime_type,
                                "timestamp": log.get("ts")
                            })
                
                # Suspicious patterns
                # SQL injection patterns
                if uri and any(pattern in uri.lower() for pattern in ["select", "union", "insert", "drop", "delete"]):
                    analysis["suspicious_requests"].append({
                        "type": "potential_sqli",
                        "host": host,
                        "uri": uri[:100],
                        "method": method
                    })
                
                # XSS patterns
                if uri and any(pattern in uri.lower() for pattern in ["<script", "javascript:", "onerror="]):
                    analysis["suspicious_requests"].append({
                        "type": "potential_xss",
                        "host": host,
                        "uri": uri[:100],
                        "method": method
                    })
            
            # Sort and limit
            analysis["top_hosts"] = dict(sorted(analysis["top_hosts"].items(), key=lambda x: x[1], reverse=True)[:20])
            analysis["top_uris"] = dict(sorted(analysis["top_uris"].items(), key=lambda x: x[1], reverse=True)[:20])
            analysis["user_agents"] = dict(sorted(analysis["user_agents"].items(), key=lambda x: x[1], reverse=True)[:10])
            analysis["file_downloads"] = analysis["file_downloads"][:20]
            analysis["suspicious_requests"] = analysis["suspicious_requests"][:20]
            
            logger.info(f"Analyzed {len(http_logs)} Zeek HTTP logs")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing Zeek HTTP: {e}")
            return {}
    
    async def analyze_zeek_files(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze Zeek file logs for file transfers and types"""
        try:
            zeek_logs = await self.get_local_zeek_logs(log_types=["files"], hours=hours, limit=5000)
            file_logs = zeek_logs.get("files", [])
            
            analysis = {
                "total_files": len(file_logs),
                "mime_types": {},
                "sources": {},
                "file_sizes": {"total": 0, "avg": 0, "max": 0},
                "large_files": [],
                "executable_files": []
            }
            
            if not file_logs:
                return analysis
            
            file_sizes = []
            
            for log in file_logs:
                # MIME type analysis
                mime_type = log.get("mime_type", "unknown")
                analysis["mime_types"][mime_type] = analysis["mime_types"].get(mime_type, 0) + 1
                
                # Source protocol
                source = log.get("source", "unknown")
                analysis["sources"][source] = analysis["sources"].get(source, 0) + 1
                
                # File size analysis
                total_bytes = log.get("total_bytes")
                if total_bytes and isinstance(total_bytes, (int, float)):
                    file_sizes.append(total_bytes)
                    
                    # Track large files (> 10MB)
                    if total_bytes > LARGE_FILE_THRESHOLD_BYTES:
                        analysis["large_files"].append({
                            "mime_type": mime_type,
                            "size_mb": total_bytes / 1000000,
                            "source": source,
                            "timestamp": log.get("ts")
                        })
                
                # Track executable files
                if mime_type and any(t in mime_type for t in ["application/x-executable", "application/x-dosexec", "application/x-sharedlib"]):
                    analysis["executable_files"].append({
                        "mime_type": mime_type,
                        "source": source,
                        "size_bytes": total_bytes,
                        "timestamp": log.get("ts")
                    })
            
            # Calculate file size stats
            if file_sizes:
                analysis["file_sizes"]["total"] = sum(file_sizes)
                analysis["file_sizes"]["avg"] = sum(file_sizes) / len(file_sizes)
                analysis["file_sizes"]["max"] = max(file_sizes)
            
            # Limit lists
            analysis["large_files"] = analysis["large_files"][:20]
            analysis["executable_files"] = analysis["executable_files"][:20]
            
            logger.info(f"Analyzed {len(file_logs)} Zeek file logs")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing Zeek files: {e}")
            return {}
    
    async def close(self):
        """Close HTTP client"""
        await self.http_client.aclose()