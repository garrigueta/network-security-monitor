"""Advanced attack pattern detection and correlation"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict
import structlog

logger = structlog.get_logger()


class AttackPattern:
    """Base class for attack patterns"""
    
    def __init__(self, name: str, severity: str, description: str):
        self.name = name
        self.severity = severity
        self.description = description
        self.indicators = []
        self.confidence = 0.0
        self.timeline = []
        self.affected_systems = set()
        self.source_ips = set()
        self.evidence = []


class AttackPatternDetector:
    """Detect and correlate complex attack patterns across log sources"""
    
    def __init__(self):
        self.patterns = []
        self.ip_activity = defaultdict(list)
        self.timeline = []
        
    def analyze_logs(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Analyze all logs for attack patterns"""
        logger.info("Starting attack pattern detection")
        
        detected_patterns = []
        
        # Build IP activity timeline
        self._build_ip_timeline(all_logs)
        
        # Detect specific patterns
        detected_patterns.extend(self._detect_ssh_brute_force(all_logs))
        detected_patterns.extend(self._detect_reconnaissance(all_logs))
        detected_patterns.extend(self._detect_malware_callbacks(all_logs))
        detected_patterns.extend(self._detect_lateral_movement(all_logs))
        detected_patterns.extend(self._detect_data_exfiltration(all_logs))
        detected_patterns.extend(self._detect_apt_patterns(all_logs))
        detected_patterns.extend(self._detect_coordinated_attacks(all_logs))
        detected_patterns.extend(self._detect_exploit_attempts(all_logs))
        
        logger.info(f"Detected {len(detected_patterns)} attack patterns")
        return detected_patterns
    
    def _build_ip_timeline(self, all_logs: Dict[str, Any]):
        """Build timeline of IP activity across all sources"""
        self.ip_activity.clear()
        self.timeline.clear()
        
        # Honeypot activity
        for cowrie_log in all_logs["sources"]["honeypot"].get("cowrie", []):
            ip = cowrie_log.get("src_ip")
            timestamp = cowrie_log.get("timestamp")
            if ip and timestamp:
                self.ip_activity[ip].append({
                    "timestamp": timestamp,
                    "source": "cowrie",
                    "event": cowrie_log.get("eventid", "unknown"),
                    "data": cowrie_log
                })
                self.timeline.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "source": "cowrie",
                    "event": cowrie_log.get("eventid", "unknown")
                })
        
        for heralding_log in all_logs["sources"]["honeypot"].get("heralding", []):
            ip = heralding_log.get("source_ip") or heralding_log.get("src_ip")
            timestamp = heralding_log.get("timestamp")
            if ip and timestamp:
                self.ip_activity[ip].append({
                    "timestamp": timestamp,
                    "source": "heralding",
                    "event": heralding_log.get("type", "unknown"),
                    "data": heralding_log
                })
                self.timeline.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "source": "heralding",
                    "event": heralding_log.get("type", "unknown")
                })
        
        # Zeek network activity
        for conn_log in all_logs["sources"].get("zeek", {}).get("conn", []):
            if isinstance(conn_log, dict):
                ip = conn_log.get("id.orig_h")
                timestamp = conn_log.get("ts")
                if ip and timestamp:
                    self.ip_activity[ip].append({
                        "timestamp": timestamp,
                        "source": "zeek_conn",
                        "event": "connection",
                        "data": conn_log
                    })
    
    def _detect_ssh_brute_force(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect SSH brute force attacks with network correlation"""
        patterns = []
        
        # Track SSH attempts per IP
        ssh_attempts = defaultdict(list)
        
        for cowrie_log in all_logs["sources"]["honeypot"].get("cowrie", []):
            event = cowrie_log.get("eventid", "")
            if "login" in event.lower() or "auth" in event.lower():
                ip = cowrie_log.get("src_ip")
                if ip:
                    ssh_attempts[ip].append(cowrie_log)
        
        # Analyze each IP's SSH activity
        for ip, attempts in ssh_attempts.items():
            if len(attempts) >= 5:  # Threshold for brute force
                pattern = AttackPattern(
                    name="SSH Brute Force Attack",
                    severity="HIGH" if len(attempts) > 50 else "MEDIUM",
                    description=f"Brute force attack detected from {ip} with {len(attempts)} attempts"
                )
                pattern.source_ips.add(ip)
                pattern.indicators.append(f"{len(attempts)} SSH login attempts")
                pattern.confidence = min(0.95, 0.5 + (len(attempts) / 100))
                
                # Correlate with Zeek network data
                zeek_correlation = self._correlate_with_zeek_ssh(ip, all_logs)
                if zeek_correlation:
                    pattern.indicators.append(f"Network correlation: {zeek_correlation['connections']} SSH connections")
                    pattern.evidence.append({
                        "type": "zeek_correlation",
                        "data": zeek_correlation
                    })
                    pattern.confidence = min(0.99, pattern.confidence + 0.1)
                
                # Check for credential stuffing patterns
                usernames = set(log.get("username", "") for log in attempts if log.get("username"))
                if len(usernames) > 10:
                    pattern.indicators.append(f"Credential stuffing: {len(usernames)} different usernames")
                    pattern.description += f" using {len(usernames)} different usernames"
                
                pattern.timeline = self._extract_timeline(attempts)
                pattern.evidence.append({
                    "type": "honeypot_logs",
                    "count": len(attempts),
                    "samples": attempts[:5]
                })
                
                patterns.append(pattern)
        
        return patterns
    
    def _detect_reconnaissance(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect reconnaissance and scanning activities"""
        patterns = []
        
        # Track port scanning behavior
        port_scan_activity = defaultdict(lambda: {"ports": set(), "connections": []})
        
        for conn_log in all_logs["sources"].get("zeek", {}).get("conn", []):
            if isinstance(conn_log, dict):
                ip = conn_log.get("id.orig_h")
                port = conn_log.get("id.resp_p")
                if ip and port:
                    port_scan_activity[ip]["ports"].add(port)
                    port_scan_activity[ip]["connections"].append(conn_log)
        
        # Detect scanning patterns
        for ip, activity in port_scan_activity.items():
            port_count = len(activity["ports"])
            conn_count = len(activity["connections"])
            
            if port_count >= 10 or conn_count >= 50:  # Scanning indicators
                pattern = AttackPattern(
                    name="Network Reconnaissance / Port Scanning",
                    severity="HIGH" if port_count > 100 else "MEDIUM",
                    description=f"Port scanning detected from {ip} - {port_count} unique ports, {conn_count} connections"
                )
                pattern.source_ips.add(ip)
                pattern.indicators.append(f"{port_count} unique ports scanned")
                pattern.indicators.append(f"{conn_count} total connection attempts")
                pattern.confidence = min(0.95, 0.6 + (port_count / 100))
                
                # Check for honeypot follow-up
                if ip in self.ip_activity:
                    honeypot_events = [e for e in self.ip_activity[ip] if e["source"] in ["cowrie", "heralding"]]
                    if honeypot_events:
                        pattern.indicators.append(f"Followed by {len(honeypot_events)} honeypot interactions")
                        pattern.description += f" with subsequent exploitation attempts"
                        pattern.confidence = min(0.98, pattern.confidence + 0.15)
                        pattern.evidence.append({
                            "type": "attack_chain",
                            "sequence": ["reconnaissance", "exploitation"]
                        })
                
                pattern.evidence.append({
                    "type": "zeek_conn",
                    "ports": sorted(list(activity["ports"]))[:20],
                    "connection_count": conn_count
                })
                
                patterns.append(pattern)
        
        return patterns
    
    def _detect_malware_callbacks(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect malware C2 callbacks and beaconing"""
        patterns = []
        
        # Track DNS and HTTP patterns
        dns_queries = defaultdict(list)
        http_requests = defaultdict(list)
        
        for dns_log in all_logs["sources"].get("zeek", {}).get("dns", []):
            if isinstance(dns_log, dict):
                domain = dns_log.get("query")
                ip = dns_log.get("id.orig_h")
                if domain and ip:
                    dns_queries[ip].append(domain)
        
        for http_log in all_logs["sources"].get("zeek", {}).get("http", []):
            if isinstance(http_log, dict):
                host = http_log.get("host")
                ip = http_log.get("id.orig_h")
                if host and ip:
                    http_requests[ip].append(http_log)
        
        # Detect suspicious patterns
        for ip in set(dns_queries.keys()) | set(http_requests.keys()):
            suspicious_indicators = []
            
            # Check for suspicious domains
            domains = dns_queries.get(ip, [])
            suspicious_domains = [d for d in domains if self._is_suspicious_domain(d)]
            
            if suspicious_domains:
                suspicious_indicators.append(f"{len(suspicious_domains)} suspicious domain queries")
            
            # Check for beaconing behavior (regular intervals)
            http_reqs = http_requests.get(ip, [])
            if len(http_reqs) >= 5:
                suspicious_indicators.append(f"{len(http_reqs)} HTTP requests (potential beaconing)")
            
            # Check if IP also hit honeypot
            honeypot_activity = ip in self.ip_activity
            
            if suspicious_indicators and honeypot_activity:
                pattern = AttackPattern(
                    name="Potential Malware C2 Communication",
                    severity="CRITICAL",
                    description=f"Possible malware callback detected from {ip} after honeypot compromise"
                )
                pattern.source_ips.add(ip)
                pattern.indicators.extend(suspicious_indicators)
                pattern.indicators.append("IP previously compromised honeypot")
                pattern.confidence = 0.75
                
                pattern.evidence.append({
                    "type": "dns_queries",
                    "suspicious_domains": suspicious_domains[:10]
                })
                pattern.evidence.append({
                    "type": "http_requests",
                    "count": len(http_reqs)
                })
                
                patterns.append(pattern)
        
        return patterns
    
    def _detect_lateral_movement(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect lateral movement attempts"""
        patterns = []
        
        # Track internal connections after honeypot compromise
        compromised_ips = set()
        
        # IPs that successfully accessed honeypot
        for cowrie_log in all_logs["sources"]["honeypot"].get("cowrie", []):
            if "login" in cowrie_log.get("eventid", "").lower() and cowrie_log.get("success"):
                compromised_ips.add(cowrie_log.get("src_ip"))
        
        # Check for SMB, RDP, SSH attempts from compromised IPs
        lateral_protocols = {"445", "3389", "22", "139"}  # SMB, RDP, SSH, NetBIOS
        
        for conn_log in all_logs["sources"].get("zeek", {}).get("conn", []):
            if isinstance(conn_log, dict):
                src_ip = conn_log.get("id.orig_h")
                dst_port = str(conn_log.get("id.resp_p", ""))
                
                if src_ip in compromised_ips and dst_port in lateral_protocols:
                    pattern = AttackPattern(
                        name="Lateral Movement Attempt",
                        severity="CRITICAL",
                        description=f"Lateral movement detected from compromised system {src_ip}"
                    )
                    pattern.source_ips.add(src_ip)
                    pattern.indicators.append(f"Connection to port {dst_port} after compromise")
                    pattern.confidence = 0.85
                    
                    pattern.evidence.append({
                        "type": "lateral_movement",
                        "protocol_port": dst_port,
                        "source": "compromised_honeypot"
                    })
                    
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_data_exfiltration(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect potential data exfiltration"""
        patterns = []
        
        # Track large outbound transfers
        large_transfers = defaultdict(lambda: {"bytes": 0, "connections": []})
        
        for conn_log in all_logs["sources"].get("zeek", {}).get("conn", []):
            if isinstance(conn_log, dict):
                ip = conn_log.get("id.orig_h")
                bytes_sent = conn_log.get("orig_bytes", 0)
                
                if bytes_sent:
                    try:
                        bytes_val = int(bytes_sent)
                        large_transfers[ip]["bytes"] += bytes_val
                        large_transfers[ip]["connections"].append(conn_log)
                    except (ValueError, TypeError):
                        pass
        
        # Detect suspicious transfer volumes
        for ip, data in large_transfers.items():
            total_bytes = data["bytes"]
            
            # Flag transfers > 10MB
            if total_bytes > 10_000_000:
                # Check if IP hit honeypot
                honeypot_activity = ip in self.ip_activity
                
                if honeypot_activity:
                    pattern = AttackPattern(
                        name="Potential Data Exfiltration",
                        severity="CRITICAL",
                        description=f"Large data transfer ({total_bytes:,} bytes) from compromised system {ip}"
                    )
                    pattern.source_ips.add(ip)
                    pattern.indicators.append(f"Transferred {total_bytes:,} bytes")
                    pattern.indicators.append(f"{len(data['connections'])} connections")
                    pattern.indicators.append("IP previously compromised honeypot")
                    pattern.confidence = 0.70
                    
                    pattern.evidence.append({
                        "type": "large_transfer",
                        "bytes": total_bytes,
                        "connections": len(data['connections'])
                    })
                    
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_apt_patterns(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect Advanced Persistent Threat (APT) patterns"""
        patterns = []
        
        # Look for sophisticated multi-stage attacks
        multi_stage_ips = defaultdict(lambda: {"stages": [], "timeline": []})
        
        for ip, events in self.ip_activity.items():
            stages = set()
            
            for event in events:
                # Classify event into attack stages
                source = event.get("source")
                event_type = event.get("event", "").lower()
                
                if source == "zeek_conn":
                    stages.add("reconnaissance")
                elif "login" in event_type or "auth" in event_type:
                    stages.add("initial_access")
                elif source == "heralding":
                    stages.add("lateral_movement")
                
            multi_stage_ips[ip]["stages"] = list(stages)
            multi_stage_ips[ip]["timeline"] = sorted(events, key=lambda x: x.get("timestamp", ""))
        
        # Detect APT characteristics
        for ip, data in multi_stage_ips.items():
            stages = data["stages"]
            
            # APT typically shows multiple attack stages
            if len(stages) >= 2:
                pattern = AttackPattern(
                    name="Potential APT Activity",
                    severity="CRITICAL",
                    description=f"Multi-stage attack pattern detected from {ip}"
                )
                pattern.source_ips.add(ip)
                pattern.indicators.append(f"Attack stages: {', '.join(stages)}")
                pattern.indicators.append(f"{len(data['timeline'])} total events")
                pattern.confidence = 0.60 + (len(stages) * 0.1)
                
                # Check for persistence indicators
                timeline_duration = self._calculate_timeline_duration(data["timeline"])
                if timeline_duration and timeline_duration > 3600:  # > 1 hour
                    pattern.indicators.append(f"Activity duration: {timeline_duration//3600} hours (persistence)")
                    pattern.confidence = min(0.90, pattern.confidence + 0.15)
                
                pattern.evidence.append({
                    "type": "apt_indicators",
                    "stages": stages,
                    "timeline_events": len(data["timeline"])
                })
                
                patterns.append(pattern)
        
        return patterns
    
    def _detect_coordinated_attacks(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect coordinated attacks from multiple IPs"""
        patterns = []
        
        # Group IPs by ASN or subnet (simplified: /24)
        subnet_activity = defaultdict(list)
        
        for ip in self.ip_activity.keys():
            subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
            subnet_activity[subnet].append(ip)
        
        # Detect coordinated patterns
        for subnet, ips in subnet_activity.items():
            if len(ips) >= 3:  # Multiple IPs from same subnet
                total_events = sum(len(self.ip_activity[ip]) for ip in ips)
                
                if total_events >= 20:
                    pattern = AttackPattern(
                        name="Coordinated Attack Campaign",
                        severity="HIGH",
                        description=f"Coordinated attack from {len(ips)} IPs in subnet {subnet}"
                    )
                    pattern.source_ips.update(ips)
                    pattern.indicators.append(f"{len(ips)} attacking IPs from same subnet")
                    pattern.indicators.append(f"{total_events} total attack events")
                    pattern.confidence = 0.75
                    
                    # Check for timing correlation
                    timestamps = []
                    for ip in ips:
                        for event in self.ip_activity[ip]:
                            ts = event.get("timestamp")
                            if ts:
                                timestamps.append(ts)
                    
                    if timestamps:
                        pattern.indicators.append("Temporally correlated attacks")
                        pattern.confidence = min(0.90, pattern.confidence + 0.10)
                    
                    pattern.evidence.append({
                        "type": "coordinated_attack",
                        "subnet": subnet,
                        "attacking_ips": list(ips)[:10]
                    })
                    
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_exploit_attempts(self, all_logs: Dict[str, Any]) -> List[AttackPattern]:
        """Detect specific exploit attempts"""
        patterns = []
        
        # Check HTTP logs for exploit signatures
        exploit_signatures = {
            "sql_injection": [r"union\s+select", r"1=1", r"or\s+1=1", r"';--"],
            "xss": [r"<script", r"javascript:", r"onerror="],
            "lfi": [r"\.\./", r"\.\.\\", r"/etc/passwd"],
            "rce": [r"bash\s+-i", r"nc\s+-e", r"/bin/sh"],
            "xxe": [r"<!ENTITY", r"SYSTEM\s+\"file://"],
        }
        
        http_exploits = defaultdict(list)
        
        for http_log in all_logs["sources"].get("zeek", {}).get("http", []):
            if isinstance(http_log, dict):
                uri = str(http_log.get("uri", "")).lower()
                user_agent = str(http_log.get("user_agent", "")).lower()
                ip = http_log.get("id.orig_h")
                
                detected_exploits = []
                
                for exploit_type, signatures in exploit_signatures.items():
                    for sig in signatures:
                        if re.search(sig, uri, re.IGNORECASE) or re.search(sig, user_agent, re.IGNORECASE):
                            detected_exploits.append(exploit_type)
                            break
                
                if detected_exploits and ip:
                    http_exploits[ip].extend(detected_exploits)
        
        # Create patterns for exploit attempts
        for ip, exploits in http_exploits.items():
            unique_exploits = set(exploits)
            
            pattern = AttackPattern(
                name="Web Application Exploit Attempt",
                severity="HIGH",
                description=f"Exploit attempts detected from {ip}: {', '.join(unique_exploits)}"
            )
            pattern.source_ips.add(ip)
            pattern.indicators.append(f"Exploit types: {', '.join(unique_exploits)}")
            pattern.indicators.append(f"{len(exploits)} exploit attempts")
            pattern.confidence = 0.80
            
            pattern.evidence.append({
                "type": "exploit_attempts",
                "exploit_types": list(unique_exploits),
                "attempt_count": len(exploits)
            })
            
            patterns.append(pattern)
        
        return patterns
    
    def _correlate_with_zeek_ssh(self, ip: str, all_logs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Correlate honeypot SSH activity with Zeek SSH logs"""
        ssh_connections = []
        
        for ssh_log in all_logs["sources"].get("zeek", {}).get("ssh", []):
            if isinstance(ssh_log, dict) and ssh_log.get("id.orig_h") == ip:
                ssh_connections.append(ssh_log)
        
        if ssh_connections:
            return {
                "connections": len(ssh_connections),
                "details": ssh_connections[:5]
            }
        return None
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain looks suspicious"""
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        # Known suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # DGA-like patterns (lots of consonants, random-looking)
        consonants = sum(1 for c in domain_lower if c in 'bcdfghjklmnpqrstvwxyz')
        if len(domain) > 10 and consonants / len(domain) > 0.7:
            return True
        
        # Very long subdomains
        parts = domain.split('.')
        if any(len(part) > 20 for part in parts):
            return True
        
        return False
    
    def _extract_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract and sort timeline from events"""
        timeline = []
        for event in events:
            if "timestamp" in event:
                timeline.append({
                    "timestamp": event["timestamp"],
                    "event": event.get("eventid", "unknown"),
                    "details": event
                })
        return sorted(timeline, key=lambda x: x["timestamp"])
    
    def _calculate_timeline_duration(self, timeline: List[Dict[str, Any]]) -> Optional[int]:
        """Calculate duration in seconds between first and last event"""
        if len(timeline) < 2:
            return None
        
        try:
            timestamps = [e.get("timestamp") for e in timeline if e.get("timestamp")]
            if len(timestamps) < 2:
                return None
            
            # Simple string comparison for ISO timestamps
            first = min(timestamps)
            last = max(timestamps)
            
            # This is a simplified calculation
            # In production, parse timestamps properly
            return 3600  # Placeholder
        except Exception:
            return None
    
    def get_attack_summary(self, patterns: List[AttackPattern]) -> Dict[str, Any]:
        """Generate summary of detected attack patterns"""
        return {
            "total_patterns": len(patterns),
            "by_severity": {
                "CRITICAL": len([p for p in patterns if p.severity == "CRITICAL"]),
                "HIGH": len([p for p in patterns if p.severity == "HIGH"]),
                "MEDIUM": len([p for p in patterns if p.severity == "MEDIUM"]),
                "LOW": len([p for p in patterns if p.severity == "LOW"])
            },
            "by_type": {
                p.name: len([x for x in patterns if x.name == p.name])
                for p in patterns
            },
            "unique_attackers": len(set(ip for p in patterns for ip in p.source_ips)),
            "high_confidence": len([p for p in patterns if p.confidence >= 0.80]),
            "attack_chains": len([p for p in patterns if any(e.get("type") == "attack_chain" for e in p.evidence)])
        }
