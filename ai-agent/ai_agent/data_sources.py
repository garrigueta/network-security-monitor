"""Data collection from various monitoring sources"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
import structlog

from .config import settings
from .attack_patterns import AttackPatternDetector
from .logging_utils import ActionLogger

logger = structlog.get_logger()


class DataCollector:
    """Collects data from various monitoring infrastructure components"""
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=30.0)
    
    async def get_honeypot_logs(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get honeypot logs from Loki or local filesystem"""
        operation_start = time.time()
        logs = []
        
        ActionLogger.log_data_collection(
            logger,
            source="honeypot",
            action="get_logs",
            status="started",
            hours=hours,
            limit=limit
        )
        
        try:
            # Try reading from local filesystem first
            local_logs = await self.get_local_honeypot_logs(hours)
            if local_logs:
                ActionLogger.log_data_collection(
                    logger,
                    source="honeypot_filesystem",
                    action="read_local_logs",
                    status="completed",
                    records_count=len(local_logs)
                )
                logs.extend(local_logs)
        except Exception as e:
            ActionLogger.log_data_collection(
                logger,
                source="honeypot_filesystem",
                action="read_local_logs",
                status="failed",
                error=str(e)
            )
        
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
                
                ActionLogger.log_data_collection(
                    logger,
                    source="loki",
                    action="get_honeypot_logs",
                    status="completed",
                    records_count=len(data['data']['result'])
                )
            
        except Exception as e:
            ActionLogger.log_data_collection(
                logger,
                source="loki",
                action="get_honeypot_logs",
                status="failed",
                error=str(e)
            )
        
        duration_ms = (time.time() - operation_start) * 1000
        final_count = min(len(logs), limit) if limit else len(logs)
        
        ActionLogger.log_data_collection(
            logger,
            source="honeypot",
            action="get_logs",
            status="completed",
            records_count=final_count,
            duration_ms=duration_ms,
            hours=hours
        )
        
        return logs[:limit] if limit else logs
    
    async def get_prometheus_metrics(self, metric: str, duration: str = "1h") -> Dict[str, Any]:
        """Get metrics from Prometheus"""
        start_time = time.time()
        
        ActionLogger.log_data_collection(
            logger,
            source="prometheus",
            action="get_metrics",
            status="started",
            metric=metric,
            duration=duration
        )
        
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
            
            duration_ms = (time.time() - start_time) * 1000
            
            if data.get("status") == "success":
                result_data = data.get("data", {})
                result_count = len(result_data.get("result", []))
                
                ActionLogger.log_data_collection(
                    logger,
                    source="prometheus",
                    action="get_metrics",
                    status="completed",
                    metric=metric,
                    records_count=result_count,
                    duration_ms=duration_ms
                )
                return result_data
            else:
                ActionLogger.log_data_collection(
                    logger,
                    source="prometheus",
                    action="get_metrics",
                    status="failed",
                    metric=metric,
                    error="Query failed",
                    duration_ms=duration_ms
                )
                return {}
                
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            ActionLogger.log_data_collection(
                logger,
                source="prometheus",
                action="get_metrics",
                status="failed",
                metric=metric,
                error=str(e),
                duration_ms=duration_ms
            )
            return {}
    
    async def get_kubernetes_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """Get Kubernetes cluster health metrics from Prometheus"""
        start_time = time.time()
        
        ActionLogger.log_data_collection(
            logger,
            source="prometheus",
            action="get_kubernetes_metrics",
            status="started",
            hours=hours
        )
        
        metrics = {
            "errors": {},
            "resource_usage": {},
            "pod_status": {},
            "collection_time": datetime.now().isoformat()
        }
        
        try:
            # Container error metrics
            error_queries = {
                "oom_events": f'sum by (namespace, pod) (increase(container_oom_events_total[{hours}h]))',
                "memory_failures": f'sum by (namespace, pod, type) (increase(container_memory_failures_total[{hours}h]))',
                "network_rx_errors": f'sum by (namespace, pod) (increase(container_network_receive_errors_total[{hours}h]))',
                "network_tx_errors": f'sum by (namespace, pod) (increase(container_network_transmit_errors_total[{hours}h]))',
                "scrape_errors": 'count by (namespace, pod) (container_scrape_error > 0)'
            }
            
            # Resource usage metrics
            resource_queries = {
                "cpu_usage": 'sum by (namespace, pod) (rate(container_cpu_usage_seconds_total{container!=""}[5m]))',
                "memory_usage": 'sum by (namespace, pod) (container_memory_working_set_bytes{container!=""})',
                "memory_available": 'sum by (namespace, pod) (container_memory_available_bytes{container!=""})',
                "network_rx_bytes": 'sum by (namespace, pod) (rate(container_network_receive_bytes_total[5m]))',
                "network_tx_bytes": 'sum by (namespace, pod) (rate(container_network_transmit_bytes_total[5m]))',
            }
            
            # Pod status metrics
            status_queries = {
                "pod_restarts": 'sum by (namespace, pod) (increase(kube_pod_container_status_restarts_total[24h]))',
                "pod_phase": 'count by (phase) (kube_pod_status_phase)',
            }
            
            # Execute error queries
            for metric_name, query in error_queries.items():
                try:
                    result = await self._execute_prom_query(query)
                    metrics["errors"][metric_name] = result
                except Exception as e:
                    logger.warning(f"Failed to query {metric_name}: {e}")
                    metrics["errors"][metric_name] = {"result": [], "error": str(e)}
            
            # Execute resource queries
            for metric_name, query in resource_queries.items():
                try:
                    result = await self._execute_prom_query(query)
                    metrics["resource_usage"][metric_name] = result
                except Exception as e:
                    logger.warning(f"Failed to query {metric_name}: {e}")
                    metrics["resource_usage"][metric_name] = {"result": [], "error": str(e)}
            
            # Execute status queries (optional - may not have kube-state-metrics)
            for metric_name, query in status_queries.items():
                try:
                    result = await self._execute_prom_query(query)
                    metrics["pod_status"][metric_name] = result
                except Exception as e:
                    logger.debug(f"Status metric {metric_name} not available: {e}")
                    metrics["pod_status"][metric_name] = {"result": [], "error": str(e)}
            
            duration_ms = (time.time() - start_time) * 1000
            
            ActionLogger.log_data_collection(
                logger,
                source="prometheus",
                action="get_kubernetes_metrics",
                status="completed",
                hours=hours,
                duration_ms=duration_ms,
                metrics_collected=len(error_queries) + len(resource_queries) + len(status_queries)
            )
            
            return metrics
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            ActionLogger.log_data_collection(
                logger,
                source="prometheus",
                action="get_kubernetes_metrics",
                status="failed",
                error=str(e),
                duration_ms=duration_ms
            )
            return metrics
    
    async def _execute_prom_query(self, query: str) -> Dict[str, Any]:
        """Execute a Prometheus query and return results"""
        url = f"{settings.prometheus_url}/api/v1/query"
        params = {"query": query}
        
        response = await self.http_client.get(url, params=params)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get("status") == "success":
            return data.get("data", {})
        else:
            raise Exception(f"Query failed: {data.get('error', 'Unknown error')}")
    
    async def get_security_alerts(self, severity: str = "all", source: str = "all") -> List[Dict[str, Any]]:
        """Get security alerts from various sources"""
        start_time = time.time()
        alerts = []
        
        ActionLogger.log_data_collection(
            logger,
            source="security_alerts",
            action="get_alerts",
            status="started",
            severity=severity,
            alert_source=source
        )
        
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
            
            duration_ms = (time.time() - start_time) * 1000
            
            ActionLogger.log_data_collection(
                logger,
                source="security_alerts",
                action="get_alerts",
                status="completed",
                records_count=len(alerts),
                duration_ms=duration_ms,
                severity=severity,
                alert_source=source
            )
            
            return alerts
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            ActionLogger.log_data_collection(
                logger,
                source="security_alerts",
                action="get_alerts",
                status="failed",
                error=str(e),
                duration_ms=duration_ms
            )
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
            
            zeek_base = Path("/mnt/ssd-logs/zeek/logs/current")
            
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
    
    async def get_all_logs(self, hours: int = 24, include_raw_files: bool = False) -> Dict[str, Any]:
        """
        Collect all logs from all applications/sources
        
        Args:
            hours: Time window in hours to collect logs
            include_raw_files: Whether to include raw file paths in response
            
        Returns:
            Dictionary containing logs from all sources organized by type
        """
        all_logs = {
            "collection_timestamp": datetime.now().isoformat(),
            "time_window_hours": hours,
            "sources": {
                "honeypot": {
                    "cowrie": [],
                    "heralding": []
                },
                "zeek": {},
                "loki": {
                    "honeypot_entries": [],
                    "zeek_entries": []
                }
            },
            "summary": {
                "total_entries": 0,
                "by_source": {}
            },
            "attack_patterns": []  # Will be populated by pattern detection
        }
        
        # Collect honeypot logs from filesystem
        try:
            honeypot_logs = await self._get_all_honeypot_logs(hours)
            all_logs["sources"]["honeypot"] = honeypot_logs
            
            cowrie_count = len(honeypot_logs.get("cowrie", []))
            heralding_count = len(honeypot_logs.get("heralding", []))
            all_logs["summary"]["by_source"]["cowrie"] = cowrie_count
            all_logs["summary"]["by_source"]["heralding"] = heralding_count
            all_logs["summary"]["total_entries"] += cowrie_count + heralding_count
            
            logger.info(f"Collected {cowrie_count} Cowrie and {heralding_count} Heralding logs")
        except Exception as e:
            logger.error(f"Error collecting honeypot logs: {e}")
        
        # Collect Zeek logs from filesystem
        try:
            zeek_logs = await self._get_all_zeek_logs(hours)
            all_logs["sources"]["zeek"] = zeek_logs
            
            zeek_total = sum(len(logs) for logs in zeek_logs.values())
            all_logs["summary"]["by_source"]["zeek"] = zeek_total
            all_logs["summary"]["total_entries"] += zeek_total
            
            logger.info(f"Collected {zeek_total} Zeek log entries across {len(zeek_logs)} log types")
        except Exception as e:
            logger.error(f"Error collecting Zeek logs: {e}")
        
        # Collect logs from Loki (if available)
        try:
            loki_logs = await self._get_all_loki_logs(hours)
            all_logs["sources"]["loki"] = loki_logs
            
            loki_honeypot_count = len(loki_logs.get("honeypot_entries", []))
            loki_zeek_count = len(loki_logs.get("zeek_entries", []))
            all_logs["summary"]["by_source"]["loki_honeypot"] = loki_honeypot_count
            all_logs["summary"]["by_source"]["loki_zeek"] = loki_zeek_count
            
            logger.info(f"Collected {loki_honeypot_count} honeypot and {loki_zeek_count} Zeek entries from Loki")
        except Exception as e:
            logger.warning(f"Error collecting Loki logs: {e}")
        
        # Detect attack patterns
        try:
            detector = AttackPatternDetector()
            detected_patterns = detector.analyze_logs(all_logs)
            
            # Convert pattern objects to dictionaries
            all_logs["attack_patterns"] = [
                {
                    "name": p.name,
                    "severity": p.severity,
                    "description": p.description,
                    "confidence": p.confidence,
                    "indicators": p.indicators,
                    "source_ips": list(p.source_ips),
                    "evidence": p.evidence
                }
                for p in detected_patterns
            ]
            
            # Add pattern summary
            all_logs["attack_pattern_summary"] = detector.get_attack_summary(detected_patterns)
            
            logger.info(f"Detected {len(detected_patterns)} attack patterns")
        except Exception as e:
            logger.error(f"Error detecting attack patterns: {e}")
        
        # Add file paths if requested
        if include_raw_files:
            all_logs["file_paths"] = await self._get_log_file_paths()
        
        logger.info(f"Total logs collected: {all_logs['summary']['total_entries']} from {len(all_logs['summary']['by_source'])} sources")
        return all_logs
    
    async def _get_all_honeypot_logs(self, hours: int = 24) -> Dict[str, List[Dict[str, Any]]]:
        """Collect all honeypot logs from filesystem"""
        honeypot_logs = {
            "cowrie": [],
            "heralding": []
        }
        
        try:
            import os
            import csv
            from pathlib import Path
            
            honeypot_base = Path("/mnt/honeypot-logs")
            
            # Cowrie logs
            cowrie_path = honeypot_base / "cowrie"
            if cowrie_path.exists():
                # Read JSON logs
                for json_file in cowrie_path.glob("*.json"):
                    try:
                        with open(json_file, 'r') as f:
                            for line in f:
                                try:
                                    log_entry = json.loads(line.strip())
                                    log_entry["source"] = "cowrie"
                                    log_entry["file"] = str(json_file.name)
                                    honeypot_logs["cowrie"].append(log_entry)
                                except json.JSONDecodeError:
                                    continue
                    except Exception as e:
                        logger.warning(f"Error reading {json_file}: {e}")
                
                # Read text logs
                for log_file in cowrie_path.glob("*.log"):
                    try:
                        with open(log_file, 'r') as f:
                            for line_num, line in enumerate(f, 1):
                                if line.strip():
                                    honeypot_logs["cowrie"].append({
                                        "source": "cowrie",
                                        "file": str(log_file.name),
                                        "line_number": line_num,
                                        "message": line.strip(),
                                        "raw": True
                                    })
                    except Exception as e:
                        logger.warning(f"Error reading {log_file}: {e}")
            
            # Heralding logs
            heralding_path = honeypot_base / "heralding"
            if heralding_path.exists():
                # Read CSV logs (auth and session)
                for csv_file in heralding_path.glob("*.csv"):
                    try:
                        with open(csv_file, 'r') as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                row["source"] = "heralding"
                                row["file"] = str(csv_file.name)
                                row["type"] = "auth" if "auth" in csv_file.name else "session"
                                honeypot_logs["heralding"].append(row)
                    except Exception as e:
                        logger.warning(f"Error reading {csv_file}: {e}")
                
                # Read JSON logs
                for json_file in heralding_path.glob("*.json"):
                    try:
                        # Check if file is not empty
                        if os.path.getsize(json_file) > 0:
                            with open(json_file, 'r') as f:
                                for line in f:
                                    try:
                                        log_entry = json.loads(line.strip())
                                        log_entry["source"] = "heralding"
                                        log_entry["file"] = str(json_file.name)
                                        honeypot_logs["heralding"].append(log_entry)
                                    except json.JSONDecodeError:
                                        continue
                    except Exception as e:
                        logger.warning(f"Error reading {json_file}: {e}")
            
            logger.info(f"Collected {len(honeypot_logs['cowrie'])} Cowrie and {len(honeypot_logs['heralding'])} Heralding logs from filesystem")
            
        except Exception as e:
            logger.error(f"Error reading honeypot logs: {e}")
        
        return honeypot_logs
    
    async def _get_all_zeek_logs(self, hours: int = 24) -> Dict[str, List[Dict[str, Any]]]:
        """Collect all Zeek logs from filesystem"""
        zeek_logs = {}
        
        try:
            from pathlib import Path
            import gzip
            
            # Define all Zeek log types
            log_types = [
                "conn",      # Connection logs
                "dns",       # DNS queries
                "http",      # HTTP requests
                "ssl",       # SSL/TLS connections
                "ssh",       # SSH connections
                "files",     # File analysis
                "weird",     # Unusual/weird traffic
                "notice",    # Zeek notices/alerts
                "dhcp",      # DHCP
                "software",  # Software detection
                "x509",      # SSL certificates
                "smtp",      # Email
                "ftp",       # FTP
                "rdp",       # RDP
                "smb",       # SMB
                "snmp"       # SNMP
            ]
            
            zeek_base = Path("/mnt/ssd-logs/zeek/logs/current")
            
            for log_type in log_types:
                log_file = zeek_base / f"{log_type}.log"
                
                if log_file.exists():
                    entries = await self._parse_zeek_log(log_file, log_type)
                    if entries:
                        zeek_logs[log_type] = entries
                        logger.debug(f"Parsed {len(entries)} entries from {log_type}.log")
            
            # Also check for archived/compressed logs
            for gz_file in zeek_base.parent.glob("**/*.log.gz"):
                try:
                    log_type = gz_file.stem.replace(".log", "")
                    if log_type in log_types:
                        with gzip.open(gz_file, 'rt') as f:
                            entries = await self._parse_zeek_log_content(f, log_type, str(gz_file.name))
                            if entries:
                                if log_type not in zeek_logs:
                                    zeek_logs[log_type] = []
                                zeek_logs[log_type].extend(entries)
                except Exception as e:
                    logger.warning(f"Error reading compressed log {gz_file}: {e}")
            
            logger.info(f"Collected Zeek logs from {len(zeek_logs)} log types")
            
        except Exception as e:
            logger.error(f"Error reading Zeek logs: {e}")
        
        return zeek_logs
    
    async def _parse_zeek_log(self, log_file: Path, log_type: str) -> List[Dict[str, Any]]:
        """Parse a Zeek log file"""
        try:
            with open(log_file, 'r') as f:
                return await self._parse_zeek_log_content(f, log_type, str(log_file.name))
        except Exception as e:
            logger.error(f"Error parsing Zeek log {log_file}: {e}")
            return []
    
    async def _parse_zeek_log_content(self, file_handle, log_type: str, filename: str) -> List[Dict[str, Any]]:
        """Parse Zeek log content from file handle"""
        entries = []
        headers = []
        separator = "\t"
        
        try:
            for line in file_handle:
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Parse header information
                if line.startswith('#'):
                    if line.startswith('#separator'):
                        # Extract separator (usually \x09 for tab)
                        sep_match = line.split(' ')
                        if len(sep_match) > 1:
                            separator = sep_match[1].replace('\\x09', '\t')
                    elif line.startswith('#fields'):
                        # Extract field names
                        headers = line.replace('#fields', '').strip().split(separator)
                    continue
                
                # Parse data lines
                if headers:
                    values = line.split(separator)
                    if len(values) == len(headers):
                        entry = dict(zip(headers, values))
                        entry["log_type"] = log_type
                        entry["source"] = "zeek"
                        entry["file"] = filename
                        entries.append(entry)
                else:
                    # No headers parsed yet, store raw
                    entries.append({
                        "raw": line,
                        "log_type": log_type,
                        "source": "zeek",
                        "file": filename
                    })
        
        except Exception as e:
            logger.error(f"Error parsing Zeek log content: {e}")
        
        return entries
    
    async def _get_all_loki_logs(self, hours: int = 24) -> Dict[str, List[Dict[str, Any]]]:
        """Collect all logs from Loki"""
        loki_logs = {
            "honeypot_entries": [],
            "zeek_entries": []
        }
        
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            start_ns = int(start_time.timestamp() * 1_000_000_000)
            end_ns = int(end_time.timestamp() * 1_000_000_000)
            
            # Query honeypot logs
            try:
                honeypot_query = '{job="honeypot"}'
                url = f"{settings.loki_url}/loki/api/v1/query_range"
                params = {
                    "query": honeypot_query,
                    "start": start_ns,
                    "end": end_ns,
                    "limit": 5000
                }
                
                response = await self.http_client.get(url, params=params)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success" and data.get("data", {}).get("result"):
                        for stream in data["data"]["result"]:
                            labels = stream.get("stream", {})
                            for entry in stream.get("values", []):
                                timestamp, log_line = entry
                                try:
                                    log_data = json.loads(log_line)
                                    log_data["timestamp"] = timestamp
                                    log_data["labels"] = labels
                                    loki_logs["honeypot_entries"].append(log_data)
                                except json.JSONDecodeError:
                                    loki_logs["honeypot_entries"].append({
                                        "timestamp": timestamp,
                                        "message": log_line,
                                        "labels": labels,
                                        "raw": True
                                    })
            except Exception as e:
                logger.warning(f"Error querying Loki for honeypot logs: {e}")
            
            # Query Zeek logs
            try:
                zeek_query = '{job="zeek"}'
                params = {
                    "query": zeek_query,
                    "start": start_ns,
                    "end": end_ns,
                    "limit": 5000
                }
                
                response = await self.http_client.get(url, params=params)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success" and data.get("data", {}).get("result"):
                        for stream in data["data"]["result"]:
                            labels = stream.get("stream", {})
                            for entry in stream.get("values", []):
                                timestamp, log_line = entry
                                loki_logs["zeek_entries"].append({
                                    "timestamp": timestamp,
                                    "message": log_line,
                                    "labels": labels,
                                    "log_type": labels.get("log_type", "unknown")
                                })
            except Exception as e:
                logger.warning(f"Error querying Loki for Zeek logs: {e}")
            
        except Exception as e:
            logger.error(f"Error collecting logs from Loki: {e}")
        
        return loki_logs
    
    async def _get_log_file_paths(self) -> Dict[str, List[str]]:
        """Get all available log file paths"""
        file_paths = {
            "honeypot": {
                "cowrie": [],
                "heralding": []
            },
            "zeek": []
        }
        
        try:
            from pathlib import Path
            
            # Honeypot log paths
            honeypot_base = Path("/mnt/honeypot-logs")
            if honeypot_base.exists():
                cowrie_path = honeypot_base / "cowrie"
                if cowrie_path.exists():
                    file_paths["honeypot"]["cowrie"] = [
                        str(f.relative_to(honeypot_base)) for f in cowrie_path.glob("*")
                        if f.is_file()
                    ]
                
                heralding_path = honeypot_base / "heralding"
                if heralding_path.exists():
                    file_paths["honeypot"]["heralding"] = [
                        str(f.relative_to(honeypot_base)) for f in heralding_path.glob("*")
                        if f.is_file()
                    ]
            
            # Zeek log paths
            zeek_base = Path("/mnt/ssd-logs/zeek/logs")
            if zeek_base.exists():
                file_paths["zeek"] = [
                    str(f.relative_to(zeek_base)) for f in zeek_base.rglob("*.log*")
                    if f.is_file()
                ]
        
        except Exception as e:
            logger.error(f"Error getting log file paths: {e}")
        
        return file_paths
    
    async def close(self):
        """Close HTTP client"""
        await self.http_client.aclose()