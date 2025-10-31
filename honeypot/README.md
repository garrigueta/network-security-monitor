# Honeypot Deployment - Second Raspberry Pi

Complete honeypot setup for network security monitoring and threat intelligence gathering.

**Note**: This is for deploying on your **second Raspberry Pi device** (not the Raspberry Pi 2 model). Any Raspberry Pi 3B+, 4, or 5 is recommended for better performance.

## Overview

This honeypot deployment includes:
- **Cowrie**: SSH/Telnet honeypot for capturing brute-force attacks and commands
- **Dionaea**: Malware collection honeypot (FTP, SMB, MySQL, MSSQL, SIP)
- **HoneyTrap**: Network service emulation
- **Promtail**: Ships logs to central Loki instance
- **Node Exporter**: System metrics

## Prerequisites

- Raspberry Pi 3B+, 4, or 5 (second device for honeypot)
- Docker Engine 20.10+
- Docker Compose 2.0+
- Network connectivity to main monitoring server (RPi1)
- Minimum 2GB RAM
- Minimum 16GB SD card

## Network Architecture

```
Internet
   │
   ├──> Honeypot Pi (2nd device)  Main Monitoring Pi (1st device)
   │    ├─ Cowrie (SSH:22)        ├─ Loki
   │    ├─ Dionaea (SMB:445)      ├─ Prometheus  
   │    ├─ HoneyTrap              ├─ Grafana
   │    └─ Promtail ──────────────┘
   │
```

## Quick Start

### 1. Initial Setup on Second Raspberry Pi

```bash
# Clone the repository
git clone https://github.com/garrigueta/network-security-monitor.git
cd network-security-monitor/honeypot

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

### 2. Configure Environment

Edit `.env` file:

```bash
# IP address of your main monitoring server (first Raspberry Pi)
LOKI_URL=http://192.168.1.100:3100

# Network configuration
HONEYPOT_NETWORK=192.168.1.0/24
```

### 3. Port Forwarding (Router Configuration)

Forward these ports from your router to your second Raspberry Pi (honeypot):

| Service | External Port | Internal Port | Protocol |
|---------|---------------|---------------|----------|
| SSH Honeypot | 22 | 2222 | TCP |
| Telnet Honeypot | 23 | 2223 | TCP |
| FTP | 21 | 21 | TCP |
| SMB | 445 | 445 | TCP |
| MySQL | 3306 | 3306 | TCP |
| MSSQL | 1433 | 1433 | TCP |

**Important**: Change your actual SSH port to something else (e.g., 2222) first!

```bash
# On your second Raspberry Pi, change SSH port before deploying honeypot
sudo nano /etc/ssh/sshd_config
# Change Port 22 to Port 2222
sudo systemctl restart sshd
```

### 4. Deploy Honeypot Stack

```bash
docker-compose up -d
```

### 5. Verify Deployment

```bash
# Check running containers
docker-compose ps

# View logs
docker-compose logs -f

# Check specific honeypot
docker-compose logs -f cowrie
docker-compose logs -f dionaea
```

## Honeypot Details

### Cowrie (SSH/Telnet)

**Purpose**: Capture SSH brute-force attacks, commands, and malware downloads

**Ports**:
- 2222: SSH
- 2223: Telnet

**Logs**: `/var/log/cowrie/`
- `cowrie.json`: Structured JSON logs
- `cowrie.log`: Human-readable logs
- `tty/`: Terminal recordings

**Common Attacks Captured**:
- Brute-force login attempts
- Downloaded malware samples
- Executed commands
- Lateral movement attempts

### Dionaea (Malware Collection)

**Purpose**: Capture malware exploiting network services

**Ports**:
- 21: FTP
- 135: MS-RPC
- 445: SMB
- 1433: MSSQL
- 3306: MySQL
- 5060/5061: SIP

**Malware Storage**: `/opt/dionaea/var/lib/dionaea/binaries/`

**Common Attacks Captured**:
- EternalBlue (SMB)
- SQL injection attempts
- FTP exploits
- SIP voip attacks

### HoneyTrap (Network Services)

**Purpose**: Emulate various network services

**Features**:
- Dynamic service emulation
- Protocol-agnostic
- Low resource usage

## Grafana Dashboard

A pre-configured dashboard is included: `honeypot-attack-overview.json`

**Panels**:
1. Attacks by Honeypot Type (pie chart)
2. SSH/Telnet Attacks counter
3. Malware Connections counter
4. Attack Timeline (time series)
5. SSH Login Attempts log viewer
6. Top Attack Sources table

**Access**: http://RPi1-IP:3000
- Navigate to Dashboards → Honeypot Attack Overview

## Management Commands

### View All Logs

```bash
docker-compose logs -f
```

### View Cowrie Attacks

```bash
# Real-time JSON logs
docker-compose exec cowrie tail -f /cowrie/cowrie-git/var/log/cowrie/cowrie.json

# Recent login attempts
docker-compose exec cowrie grep "login attempt" /cowrie/cowrie-git/var/log/cowrie/cowrie.log
```

### View Downloaded Malware

```bash
# List captured malware
docker-compose exec cowrie ls -lh /cowrie/cowrie-git/var/lib/cowrie/downloads/

# Copy malware samples for analysis (BE CAREFUL!)
docker cp cowrie:/cowrie/cowrie-git/var/lib/cowrie/downloads/ ./malware-samples/
```

### View Dionaea Binaries

```bash
# List captured malware binaries
docker-compose exec dionaea ls -lh /opt/dionaea/var/lib/dionaea/binaries/
```

### Restart Services

```bash
# Restart all
docker-compose restart

# Restart specific honeypot
docker-compose restart cowrie
docker-compose restart dionaea
```

### Update Honeypots

```bash
docker-compose pull
docker-compose up -d
```

## Security Considerations

⚠️ **IMPORTANT SECURITY NOTES**:

1. **Isolate the Honeypot**: 
   - Use a separate VLAN if possible
   - Ensure honeypot cannot access internal network
   - Configure firewall rules appropriately

2. **Change Real SSH Port**:
   ```bash
   # BEFORE deploying honeypot
   sudo nano /etc/ssh/sshd_config
   # Change to: Port 2222
   sudo systemctl restart sshd
   ```

3. **Monitor Resource Usage**:
   - Honeypots can consume resources under attack
   - Set Docker resource limits if needed

4. **Malware Handling**:
   - Captured malware is DANGEROUS
   - Analyze in isolated environment only
   - Never execute on production systems

5. **Legal Considerations**:
   - Ensure honeypot deployment is legal in your jurisdiction
   - Log retention policies
   - Incident response procedures

## Firewall Configuration

### On Second Raspberry Pi (Honeypot Host)

```bash
# Allow honeypot ports
sudo ufw allow 21/tcp   # FTP
sudo ufw allow 22/tcp   # SSH honeypot (external)
sudo ufw allow 23/tcp   # Telnet
sudo ufw allow 445/tcp  # SMB
sudo ufw allow 1433/tcp # MSSQL
sudo ufw allow 2222/tcp # Real SSH
sudo ufw allow 3306/tcp # MySQL
sudo ufw allow 5060:5061/tcp # SIP

# Allow Promtail to reach Loki on first Raspberry Pi
sudo ufw allow out to 192.168.1.100 port 3100

# Enable firewall
sudo ufw enable
```

## Customization

### Add Custom SSH Credentials

Edit `cowrie/cowrie.cfg`:

```ini
[database_textfile]
file = etc/userdb.txt
```

Create custom credential file in the Cowrie container.

### Change Honeypot Hostname

Edit `cowrie/cowrie.cfg`:

```ini
[honeypot]
hostname = your-custom-hostname
```

### Add More Services to HoneyTrap

Edit `honeytrap/honeytrap.yml`:

```yaml
services:
  - type: custom-service
    port: 8080
    credentials:
      - username: user
        password: pass
```

## Monitoring and Alerts

### Loki Queries for Honeypot

Access Loki on RPi1 and use these queries:

```logql
# All honeypot activity
{job="honeypot"}

# SSH attacks only
{job="honeypot", honeypot_type="cowrie"}

# Malware connections
{job="honeypot", honeypot_type="dionaea"}

# Attacks from specific IP
{job="honeypot"} |~ "192.168.1.1"

# Failed login attempts
{job="honeypot", honeypot_type="cowrie"} |~ "login attempt"

# Count attacks by source
sum by (src_ip) (count_over_time({job="honeypot"}[24h]))
```

## Troubleshooting

### Honeypot Not Receiving Connections

1. Check port forwarding on router
2. Verify firewall rules on second Raspberry Pi
3. Check Docker container status: `docker-compose ps`
4. View container logs: `docker-compose logs [service]`

### Logs Not Appearing in Grafana

1. Check Promtail is running: `docker-compose ps promtail`
2. Verify Loki URL in `.env`: `echo $LOKI_URL`
3. Test connectivity: `curl http://MAIN-PI-IP:3100/ready`
4. Check Promtail logs: `docker-compose logs promtail`

### High Resource Usage

```bash
# Check resource usage
docker stats

# Limit resources in docker-compose.yml:
services:
  cowrie:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
```

### Container Won't Start

```bash
# Check logs
docker-compose logs [service]

# Remove and recreate
docker-compose down
docker-compose up -d

# Clean rebuild
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

## Data Analysis

### Export Attack Data

```bash
# Export Cowrie JSON logs
docker cp cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ./analysis/

# Analyze with jq
cat cowrie.json | jq '.src_ip' | sort | uniq -c | sort -rn | head -10
```

### Common Analysis Tasks

```bash
# Top attacking IPs
cat cowrie.json | jq -r '.src_ip' | sort | uniq -c | sort -rn

# Most common usernames tried
cat cowrie.json | jq -r '.username' | sort | uniq -c | sort -rn

# Most common passwords tried
cat cowrie.json | jq -r '.password' | sort | uniq -c | sort -rn

# Commands executed
cat cowrie.json | jq -r 'select(.input != null) | .input' | sort | uniq -c
```

## Backup and Maintenance

### Backup Logs and Malware

```bash
# Create backup directory
mkdir -p ~/honeypot-backups/$(date +%Y%m%d)

# Backup Cowrie logs
docker cp cowrie:/cowrie/cowrie-git/var/log/ ~/honeypot-backups/$(date +%Y%m%d)/cowrie-logs/

# Backup malware samples
docker cp cowrie:/cowrie/cowrie-git/var/lib/cowrie/downloads/ ~/honeypot-backups/$(date +%Y%m%d)/malware/
docker cp dionaea:/opt/dionaea/var/lib/dionaea/binaries/ ~/honeypot-backups/$(date +%Y%m%d)/binaries/
```

### Clean Old Logs

```bash
# Clean logs older than 30 days
docker-compose exec cowrie find /cowrie/cowrie-git/var/log/ -type f -mtime +30 -delete
```

## Integration with Main Monitoring Stack

The honeypot automatically integrates with your main monitoring stack through Promtail → Loki → Grafana.

**On your main Raspberry Pi**, the dashboard will show:
- Real-time attack statistics
- Geographic distribution (if GeoIP enabled)
- Attack patterns and trends
- Top attackers and credentials tried

## Advanced Configuration

### Enable GeoIP for Attack Mapping

Edit `promtail/promtail-config.yml` to add GeoIP enrichment for attack source visualization.

### Set Up Alerts

Create Loki alerts for:
- High volume of attacks
- Attacks from specific countries
- Successful malware downloads
- Suspicious command patterns

## Support

For issues:
- Check logs: `docker-compose logs [service]`
- Verify network connectivity to RPi1
- Review firewall rules
- Check Docker container status

## License

This honeypot configuration is provided for educational and security research purposes only.
