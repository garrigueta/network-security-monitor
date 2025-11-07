# Attack Pattern Correlation Implementation

## Overview
Advanced correlation logic has been implemented to detect specific attack patterns across all log sources (honeypots, Zeek network monitoring, and Loki aggregation).

## Architecture

### Components

1. **AttackPatternDetector** (`ai_agent/attack_patterns.py`)
   - Core detection engine with 8 specialized pattern detectors
   - Cross-source correlation with IP timeline building
   - Confidence scoring and severity classification

2. **Data Source Integration** (`ai_agent/data_sources.py`)
   - Automatic pattern detection in `get_all_logs()` method
   - Returns detected patterns with comprehensive evidence

3. **Report Generation** (`ai_agent/reports/generator.py`)
   - Enhanced executive, technical, and detailed reports
   - Pattern-based vulnerability assessment
   - IOC extraction from detected patterns

## Detected Attack Patterns

### 1. SSH Brute Force with Network Correlation
- **Detection Method**: Failed login attempts + Zeek SSH correlation
- **Evidence**: Multiple failed logins from same IP, SSH connection patterns
- **Severity**: HIGH/CRITICAL (based on attempt count)
- **Confidence**: High when correlated across honeypot + Zeek logs

### 2. Reconnaissance & Port Scanning
- **Detection Method**: Port scan detection in Zeek + honeypot connection patterns
- **Evidence**: Multiple ports from same IP, rapid connection attempts
- **Severity**: MEDIUM/HIGH
- **Confidence**: High with Zeek port scan notices

### 3. Malware C2 Callbacks
- **Detection Method**: Suspicious DNS queries + HTTP beaconing patterns
- **Evidence**: Known malicious domains, regular callback intervals
- **Severity**: CRITICAL
- **Confidence**: High with domain reputation correlation

### 4. Lateral Movement Detection
- **Detection Method**: Post-compromise activity patterns
- **Evidence**: Multiple honeypot interactions, privilege escalation attempts
- **Severity**: HIGH/CRITICAL
- **Confidence**: Medium to High based on sequence

### 5. Data Exfiltration
- **Detection Method**: Large data transfers in Zeek logs
- **Evidence**: High-volume connections, suspicious destinations
- **Severity**: CRITICAL
- **Confidence**: Medium to High

### 6. APT Pattern Detection
- **Detection Method**: Multi-stage attack sequences
- **Evidence**: Reconnaissance → Exploitation → Persistence chains
- **Severity**: CRITICAL
- **Confidence**: High with complete attack chain evidence

### 7. Coordinated Attack Campaigns
- **Detection Method**: Distributed attacks from same subnet
- **Evidence**: Multiple IPs from same /24, synchronized timing
- **Severity**: HIGH
- **Confidence**: High with subnet coordination

### 8. Web Exploit Attempts
- **Detection Method**: HTTP path traversal, SQL injection, XSS patterns
- **Evidence**: Malicious HTTP URIs, exploit signatures
- **Severity**: HIGH/CRITICAL
- **Confidence**: High with signature matching

## Data Flow

```
┌─────────────────┐
│  Log Sources    │
│  - Cowrie       │
│  - Heralding    │
│  - Zeek         │
│  - Loki         │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  get_all_logs()             │
│  - Collect all logs         │
│  - Parse Zeek TSV files     │
│  - Aggregate from Loki      │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  AttackPatternDetector      │
│  - Build IP timelines       │
│  - Run 8 pattern detectors  │
│  - Calculate confidence     │
│  - Classify severity        │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Response Structure         │
│  - logs: {...}              │
│  - attack_patterns: [...]   │
│  - attack_pattern_summary   │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Report Generation          │
│  - Format patterns for AI   │
│  - Add to vulnerability     │
│    assessment               │
│  - Build evidence chains    │
│  - Extract pattern IOCs     │
└─────────────────────────────┘
```

## Response Structure

### get_all_logs() Response
```json
{
  "sources": {
    "honeypot": {...},
    "zeek": {...},
    "loki": {...}
  },
  "summary": {...},
  "attack_patterns": [
    {
      "name": "SSH Brute Force from 192.168.1.100",
      "type": "brute_force",
      "severity": "HIGH",
      "confidence": 0.95,
      "description": "Detected SSH brute force attack...",
      "affected_ips": ["192.168.1.100"],
      "evidence": [
        "50 failed login attempts in 5 minutes",
        "Zeek SSH correlation confirmed",
        "Multiple username attempts"
      ],
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ],
  "attack_pattern_summary": {
    "total_patterns": 15,
    "by_severity": {
      "CRITICAL": 3,
      "HIGH": 7,
      "MEDIUM": 5
    },
    "by_type": {
      "brute_force": 5,
      "reconnaissance": 4,
      "malware": 2,
      "lateral_movement": 1,
      "data_exfiltration": 1,
      "apt": 1,
      "coordinated": 1
    }
  }
}
```

## Report Enhancements

### Executive Report
- **Security Score**: Adjusted based on detected pattern severity
- **Threat Level**: Elevated for CRITICAL patterns
- **Key Findings**: Highlights high-confidence attack patterns
- **Pattern Metrics**: Count of detected patterns by severity

### Technical Report
- **Attack Vectors**: Includes pattern-based vectors with evidence count
- **Vulnerability Assessment**: Pattern-based vulnerabilities with affected IPs
- **AI Analysis**: Enhanced with pattern insights and correlation data

### Detailed Report
- **Evidence Chain**: Pattern evidence with source references
- **IOC Analysis**: Pattern-based IOCs with confidence levels
- **Pattern Forensics**: Complete attack pattern details with timestamps

## Cross-Source Correlation

### IP Timeline Building
```python
ip_timeline = {
  "192.168.1.100": {
    "honeypot_events": [...],
    "zeek_connections": [...],
    "timestamps": [...]
  }
}
```

### Correlation Examples

1. **SSH Brute Force + Network**:
   - Honeypot: 50 failed SSH logins
   - Zeek: SSH connections from same IP
   - Confidence: 0.95 (both sources confirm)

2. **Reconnaissance → Exploitation**:
   - Zeek: Port scan detected
   - Honeypot: Connection to scanned ports
   - Confidence: 0.85 (sequence confirmed)

3. **Malware C2**:
   - Zeek DNS: Suspicious domain queries
   - Zeek HTTP: Regular beaconing pattern
   - Confidence: 0.90 (pattern confirmed)

## Configuration

### Pattern Detection Thresholds
- **SSH Brute Force**: 10+ failed attempts in 10 minutes
- **Port Scan**: 10+ ports from same IP in 5 minutes
- **Data Exfiltration**: 100MB+ transfer
- **C2 Beaconing**: Regular intervals (60-300s tolerance)

### Severity Classification
- **CRITICAL**: APT, malware C2, data exfiltration
- **HIGH**: Brute force (100+ attempts), coordinated attacks
- **MEDIUM**: Reconnaissance, single exploits

### Confidence Scoring
- **0.9-1.0**: High - Multi-source correlation
- **0.7-0.9**: Medium - Single source with strong indicators
- **0.5-0.7**: Low - Potential pattern with limited evidence

## Usage Examples

### Generate Report with Pattern Detection
```python
# Automatically includes attack pattern detection
report = await report_generator.generate_report(
    level=ReportLevel.EXECUTIVE,
    period_hours=24
)
```

### Access Pattern Data
```python
# Get all logs with detected patterns
all_logs = await data_sources.get_all_logs(hours=24)

patterns = all_logs["attack_patterns"]
for pattern in patterns:
    print(f"{pattern['name']}: {pattern['severity']} ({pattern['confidence']:.2f})")
    print(f"Evidence: {len(pattern['evidence'])} items")
    print(f"Affected IPs: {pattern['affected_ips']}")
```

### Filter by Severity
```python
critical_patterns = [
    p for p in patterns 
    if p["severity"] == "CRITICAL"
]
```

## Benefits

1. **Automated Threat Detection**: No manual log analysis required
2. **Cross-Source Correlation**: Identifies attack chains invisible in single sources
3. **Evidence-Based**: Provides specific evidence for each detected pattern
4. **Confidence Scoring**: Prioritizes high-confidence threats
5. **AI Integration**: Enhanced AI analysis with pattern context
6. **Actionable Intelligence**: Pattern-based IOCs and affected resources

## Future Enhancements

1. **Machine Learning**: Train models on historical patterns
2. **Real-time Alerting**: Immediate notification for CRITICAL patterns
3. **Automated Response**: Trigger firewall rules for detected threats
4. **Threat Intelligence**: Integrate external threat feeds
5. **Pattern Customization**: User-defined pattern rules
6. **Performance Optimization**: Caching and incremental analysis

## Testing

To validate pattern detection with sample logs:

```bash
# Generate test logs
cd test-simulator
python main.py --duration 3600 --attack-types brute_force,reconnaissance

# Generate report
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"level": "executive", "period_hours": 1}'

# Check patterns
curl http://localhost:8000/api/v1/logs/all?hours=1 | jq '.attack_patterns'
```

## Performance Considerations

- **Memory**: Pattern detection processes all logs in memory
- **CPU**: 8 detection algorithms run sequentially
- **Optimization**: Consider async pattern detection for large datasets
- **Caching**: IP timelines could be cached for incremental updates

## Conclusion

The attack pattern correlation implementation provides comprehensive threat detection across all monitoring sources, enabling automated identification of sophisticated attack campaigns that would be missed by analyzing logs in isolation.
