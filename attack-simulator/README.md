# Advanced Attack Simulator

A sophisticated multi-protocol attack simulator designed to test honeypot detection systems and validate security monitoring capabilities.

## Features

### Supported Protocols
- **SSH** (Port 2222) - Brute force attacks with common credentials
- **Telnet** (Port 2223) - Connection attempts and banner grabbing
- **FTP** (Port 21) - Anonymous and authenticated access attempts
- **HTTP** (Port 80) - Path scanning, directory traversal, vulnerability probing
- **HTTPS** (Port 443) - SSL/TLS connection testing
- **SMTP** (Port 25) - Email server enumeration
- **MySQL** (Port 3306) - Database brute force
- **PostgreSQL** (Port 5432) - Database connection attempts
- **POP3/IMAP** (Ports 110, 143, 993, 995) - Email protocol testing
- **SOCKS5** (Port 1080) - Proxy connection attempts
- **VNC** (Port 5900) - Remote desktop scanning

### Attack Scenarios
1. **SSH Brute Force** - Tests common username/password combinations
2. **Telnet Scanning** - Automated login attempts
3. **FTP Anonymous Access** - Tests for anonymous FTP access
4. **HTTP Path Scanning** - Probes for common vulnerable paths
5. **MySQL Brute Force** - Database credential testing
6. **PostgreSQL Scanning** - Database enumeration

### Advanced Features
- ⏱️ **Randomized Timing** - Adds jitter to simulate human-like behavior
- 🎭 **Fake User Agents** - Random browser identification for HTTP attacks
- 📊 **Detailed Logging** - Color-coded output with timestamps
- 💾 **Result Persistence** - Saves attack results to JSON files
- 🔀 **Randomized Order** - Varies attack sequences to avoid patterns
- 🎯 **Configurable Scenarios** - YAML-based configuration for easy customization

## Installation

```bash
cd /home/gueta/network-security-monitor/attack-simulator

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
# Run attack simulation
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

### Customize Attack Scenarios
Edit `config.yaml` and set `enabled: false` for scenarios you want to skip:

```yaml
scenarios:
  - name: "ssh_bruteforce"
    enabled: false  # Skip this one
```

### Customize Attack Patterns
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
2025-11-02 14:45:23 - INFO - Attack Simulator initialized
2025-11-02 14:45:23 - INFO - Target: 192.168.1.135
2025-11-02 14:45:25 - INFO - [SSH] FAILED - 192.168.1.135:2222 (user: root) - Authentication failed
2025-11-02 14:45:28 - INFO - [FTP] SUCCESS - 192.168.1.135:21 (user: anonymous)
```

### JSON Results
Results are saved to `./results/attack_results_YYYYMMDD_HHMMSS.json`:

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

## Integration with AI Agent

The attack simulator generates logs that will be captured by your honeypot and analyzed by the AI agent. This creates a feedback loop:

1. **Simulator** → Attacks honeypot
2. **Honeypot** → Logs attacks to Loki
3. **AI Agent** → Analyzes patterns and generates reports
4. **Review** → Validate detection accuracy
5. **Improve** → Adjust detection rules and AI prompts

### Validation Workflow

```bash
# 1. Run attack simulation
python attack_simulator.py

# 2. Wait for logs to propagate (30 seconds)
sleep 30

# 3. Trigger AI report generation
curl -X POST "http://192.168.1.135:8080/reports/schedule/trigger?level=executive&period_hours=1" \
  -H "Authorization: Bearer network-security-ai-2025"

# 4. Check AI analysis
curl -s "http://192.168.1.135:8080/reports/latest/full" | jq -r '.ai_analysis'

# 5. Compare simulator results with detected attacks
diff results/attack_results_*.json <(curl -s http://192.168.1.135:3100/loki/api/v1/query?query='{job="honeypot"}')
```

## Safety Considerations

⚠️ **IMPORTANT**: This tool is designed for testing YOUR OWN honeypot systems only.

- Only use against systems you own and control
- Do not use against production systems
- Be aware of network traffic generation
- Respect rate limits to avoid overwhelming the honeypot
- Keep detailed logs for accountability

## Advanced Options

### Custom Attack Sequences
Create custom attack scripts by extending the `AttackSimulator` class:

```python
async def custom_attack(self) -> AttackResult:
    # Your custom attack logic
    pass
```

### Scheduled Attacks
Use cron with Docker:

```bash
# Run every hour
0 * * * * cd /home/gueta/network-security-monitor/attack-simulator && docker compose up
```

### Distributed Attacks
Run containers on different machines to simulate distributed attacks:

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
2. Implement attack method in `AttackSimulator` class
3. Add scenario to scenarios list
4. Test and document

## License

This tool is for educational and authorized security testing purposes only.
