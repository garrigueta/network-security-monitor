# Advanced Security Test Simulator

A sophisticated multi-protocol security test simulator designed to validate honeypot detection systems and test security monitoring capabilities.

## Features

### Supported Protocols
- **SSH** (Port 2222) - Brute force testing with common credentials
- **Telnet** (Port 2223) - Connection attempts and banner grabbing
- **FTP** (Port 21) - Anonymous and authenticated access tests
- **HTTP** (Port 80) - Path scanning, directory traversal, vulnerability probing
- **HTTPS** (Port 443) - SSL/TLS connection testing
- **SMTP** (Port 25) - Email server enumeration
- **MySQL** (Port 3306) - Database brute force testing
- **PostgreSQL** (Port 5432) - Database connection tests
- **DNS** (Port 53) - DNS tunneling and suspicious domain queries
- **Port Scanning** - TCP SYN scans across common/suspicious ports
- **Malformed Packets** - Generates Zeek "weird" events

### Test Scenarios
1. **SSH Brute Force** - Tests common username/password combinations
2. **Telnet Scanning** - Automated login attempts
3. **FTP Anonymous Access** - Tests for anonymous FTP access
4. **HTTP Path Scanning** - Probes for common vulnerable paths (admin, .git, shell.php, etc.)
5. **MySQL Brute Force** - Database credential testing
6. **PostgreSQL Scanning** - Database enumeration
7. **DNS Tunneling** - Simulates data exfiltration via DNS queries with encoded data
8. **Suspicious Domains** - Queries malicious domains (malware-c2-server.com, phishing-site.net, etc.)
9. **Port Scanning** - TCP connection attempts across common/suspicious/high ports
10. **Malformed Packets** - Generates weird network events:
    - Oversized HTTP headers (10KB+)
    - Malformed HTTP requests
    - Invalid TCP flags
    - Fragmented packet streams

### Advanced Features
- ⏱️ **Randomized Timing** - Adds jitter to simulate human-like behavior
- 🎭 **Fake User Agents** - Random browser identification including security tools (sqlmap, Nikto, Metasploit)
- 📊 **Detailed Logging** - Color-coded output with timestamps
- 💾 **Result Persistence** - Saves test results to JSON files
- 🔀 **Randomized Order** - Varies test sequences to avoid patterns
- 🎯 **Configurable Scenarios** - YAML-based configuration for easy customization
- 🌐 **DNS Events** - Generates suspicious DNS queries for SIEM/IDS detection
- 🔍 **Network Anomalies** - Creates weird packets that trigger Zeek alerts
- 🎲 **Dynamic Data** - Uses Faker library for realistic test patterns
- 🚨 **Multi-Layer Detection** - Tests honeypot, DNS monitoring, Zeek, and network IDS

## Installation

```bash
cd /home/gueta/network-security-monitor/test-simulator

# Build the Docker image
make build
# or
docker compose build
```

## Configuration

Edit `config.yaml` to customize:

```yaml
target:
  host: "192.168.1.135"  # Your honeypot IP
  ports:
    ssh: 2222
    # ... other ports

scenarios:
  - name: "ssh_bruteforce"
    enabled: true
    attempts: 10
    delay: 2  # seconds between attempts
```

## Usage

### Quick Start with Make
```bash
# Run test simulation
make run

# View logs in real-time
make logs

# Check results
make results

# Clean up
make clean
```

### Using Docker Compose Directly
```bash
# Run simulation (container stops when complete)
docker compose up

# Run in background
docker compose up -d

# View logs
docker compose logs -f

# Stop container
docker compose down
```

### Customize Test Scenarios
Edit `config.yaml` and set `enabled: false` for scenarios you want to skip:

```yaml
scenarios:
  - name: "ssh_bruteforce"
    enabled: false  # Skip this one
```

### Customize Test Patterns
Modify the `patterns` section in `config.yaml`:

```yaml
patterns:
  ssh:
    usernames: ["root", "admin", "custom_user"]
    passwords: ["password123", "custom_pass"]
```

After changing config, rebuild:
```bash
make build
```

## Output

### Console Output
```
2025-11-02 14:45:23 - INFO - Security Test Simulator initialized
2025-11-02 14:45:23 - INFO - Target: 192.168.1.135
2025-11-02 14:45:25 - INFO - [SSH] FAILED - 192.168.1.135:2222 (user: root) - Authentication failed
2025-11-02 14:45:28 - INFO - [FTP] SUCCESS - 192.168.1.135:21 (user: anonymous)
```

### JSON Results
Results are saved to `./results/test_results_YYYYMMDD_HHMMSS.json`:

```json
{
  "timestamp": "2025-11-02T14:45:23.123456",
  "scenario": "ssh_bruteforce",
  "protocol": "ssh",
  "target": "192.168.1.135",
  "port": 2222,
  "username": "root",
  "success": false,
  "error": "Authentication failed",
  "response_time": 2.345
}
```

## What Gets Detected

The simulator triggers multiple monitoring systems:

### Honeypot Detection (Cowrie/Heralding)
✅ SSH brute force tests  
✅ Telnet connection tests  
✅ FTP authentication tests  
✅ MySQL/PostgreSQL connection tests  
✅ All login attempts logged with credentials

### Zeek Network Monitoring
✅ DNS queries (weird domains detected)  
✅ HTTP unusual requests (oversized headers, malformed)  
✅ Port scan patterns  
✅ TCP connection anomalies  
✅ Protocol violations (weird.log events)  
✅ SSL/TLS certificate validation

### Loki Log Aggregation
✅ All honeypot events indexed  
✅ Searchable by service, IP, protocol  
✅ Time-series test patterns  

### Prometheus Metrics
✅ Test rate per minute  
✅ Service availability  
✅ Resource usage during testing

### AI Agent Analysis
✅ Pattern recognition (automated tools detected)  
✅ Threat level assessment  
✅ Test attribution (tool signatures)  
✅ Recommendations generation  
✅ Trend analysis over time

## Integration with AI Agent

The test simulator generates logs that will be captured by your honeypot and analyzed by the AI agent. This creates a feedback loop:

1. **Simulator** → Tests honeypot
2. **Honeypot** → Logs events to Loki
3. **AI Agent** → Analyzes patterns and generates reports
4. **Review** → Validate detection accuracy
5. **Improve** → Adjust detection rules and AI prompts

### Validation Workflow

```bash
# 1. Run test simulation
docker compose up

# 2. Wait for logs to propagate (30 seconds)
sleep 30

# 3. Trigger AI report generation
curl -X POST "http://192.168.1.135:8080/reports/schedule/trigger?level=executive&period_hours=1" \
  -H "Authorization: Bearer network-security-ai-2025"

# 4. Check AI analysis
curl -s "http://192.168.1.135:8080/reports/latest/full" | jq -r '.ai_analysis'

# 5. Compare simulator results with detected events
diff results/test_results_*.json <(curl -s http://192.168.1.135:3100/loki/api/v1/query?query='{job="honeypot"}')
```

## Safety Considerations

⚠️ **IMPORTANT**: This tool is designed for testing YOUR OWN honeypot systems only.

- Only use against systems you own and control
- Do not use against production systems
- Be aware of network traffic generation
- Respect rate limits to avoid overwhelming the honeypot
- Keep detailed logs for accountability

## Advanced Options

### Custom Test Sequences
Create custom test scripts by extending the test classes:

```python
async def custom_test(self) -> TestResult:
    # Your custom test logic
    pass
```

### Scheduled Tests
Use cron with Docker:

```bash
# Run every hour
0 * * * * cd /home/gueta/network-security-monitor/test-simulator && docker compose up
```

### Distributed Tests
Run containers on different machines to simulate distributed testing:

```bash
# On machine 1
docker compose up

# On machine 2 (edit config.yaml with different patterns)
docker compose up
```

## Troubleshooting

### Connection Timeouts
Increase timeout values in the code or check network connectivity:
```bash
ping 192.168.1.135
telnet 192.168.1.135 2222
```

### Build Errors
Rebuild the image from scratch:
```bash
docker compose build --no-cache
```

### Container Not Starting
Check logs for errors:
```bash
docker compose logs
```

## Contributing

To add support for new protocols:

1. Add protocol configuration to `config.yaml`
2. Create a new test class in `simulator/tests/`
3. Add scenario to scenarios list
4. Test and document

## License

This tool is for educational and authorized security testing purposes only.
