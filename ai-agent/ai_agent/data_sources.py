"""Data collection from various monitoring sources"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import httpx
import structlog

from .config import settings

logger = structlog.get_logger()


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
    
    async def get_local_zeek_logs(self, log_types: List[str] = None, hours: int = 24) -> Dict[str, List[Dict[str, Any]]]:
        """Read Zeek logs directly from local filesystem"""
        zeek_logs = {}
        
        try:
            from pathlib import Path
            
            if log_types is None:
                log_types = ["conn", "dns", "http", "ssl", "ssh"]
            
            zeek_base = Path("/mnt/zeek-logs/logs/current")
            
            for log_type in log_types:
                log_file = zeek_base / f"{log_type}.log"
                if log_file.exists():
                    logger.info(f"Reading Zeek {log_type} logs from {log_file}")
                    entries = []
                    
                    with open(log_file, 'r') as f:
                        for line in f:
                            # Skip comments and empty lines
                            if line.startswith('#') or not line.strip():
                                continue
                            
                            try:
                                # Parse TSV format
                                values = line.strip().split('\t')
                                # Basic parsing - would need proper field mapping
                                entry = {
                                    "raw": line.strip(),
                                    "log_type": log_type,
                                    "source": "zeek"
                                }
                                entries.append(entry)
                            except Exception:
                                continue
                    
                    zeek_logs[log_type] = entries
                    logger.info(f"Retrieved {len(entries)} entries from {log_type}.log")
            
            return zeek_logs
            
        except Exception as e:
            logger.error(f"Error reading local Zeek logs: {e}")
            return {}
    
    async def close(self):
        """Close HTTP client"""
        await self.http_client.aclose()