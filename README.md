# Network Security Monitoring Stack

Complete containerized network security monitoring and threat intelligence platform for Raspberry Pi.

## 📦 What's Included

**Monitoring Stack** (`monitoring/`) - Main Raspberry Pi
- Zeek network security monitor
- Prometheus metrics collection
- Loki log aggregation
- Grafana dashboards
- Cryptocurrency price tracking

**Honeypot Stack** (`honeypot/`) - Optional second device
- Cowrie SSH/Telnet honeypot
- Dionaea malware collection
- HoneyTrap service emulation
- Integrated with main monitoring

## � Quick Start

### Main Monitoring Stack

```bash
git clone https://github.com/garrigueta/network-security-monitor.git
cd network-security-monitor/monitoring

# Configure
cp .env.example .env
nano .env  # Set ZEEK_INTERFACE=your-interface

# Deploy
docker-compose up -d

# Access Grafana
open http://localhost:3000  # admin/admin
```

**📖 Full documentation**: [monitoring/README.md](monitoring/README.md)

### Honeypot Stack (Optional)

Deploy on a second Raspberry Pi to capture attack data:

```bash
cd network-security-monitor/honeypot

# Configure
cp .env.example .env
nano .env  # Set LOKI_URL=http://main-pi-ip:3100

# Deploy
docker-compose up -d
```

**📖 Full documentation**: [honeypot/README.md](honeypot/README.md)

---

## 📁 Project Structure

```
```
network-security-monitor/
├── monitoring/          # Main stack - deploy on primary Raspberry Pi
│   ├── README.md        # Complete monitoring stack documentation
│   └── ...
└── honeypot/            # Optional - deploy on second Raspberry Pi
    ├── README.md        # Complete honeypot documentation
    └── ...
```

## 📖 Documentation

- **Monitoring Stack**: [monitoring/README.md](monitoring/README.md) - Full setup guide, troubleshooting, customization
- **Honeypot Stack**: [honeypot/README.md](honeypot/README.md) - Honeypot deployment and attack analysis

## ✨ Features

- Fully containerized with Docker Compose
- Auto-provisioned Grafana dashboards
- Network traffic analysis with Zeek
- Centralized logging with Loki
- Optional honeypot integration
- Cryptocurrency price tracking

## 🔗 Links

- **Repository**: https://github.com/garrigueta/network-security-monitor
- **Grafana**: http://localhost:3000 (admin/admin after deployment)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100
```

---

## 🚀 Quick Start

### Option A: Main Monitoring Stack Only

Perfect for basic network security monitoring without honeypots.

#### 1. Configuration

```bash
cd monitoring
cp .env.example .env
nano .env
```

Edit `.env` to set your network interface:

```bash
ZEEK_INTERFACE=eth1  # Change to your monitoring interface
```

#### 2. Deploy the Stack

```bash
git clone https://github.com/garrigueta/network-security-monitor.git
cd network-security-monitor/monitoring
docker-compose up -d
```

#### 3. Verify Services

Check all services are running:

```bash
docker-compose ps
```

#### 4. Access the Services

- **Grafana**: http://localhost:3000 (default: admin/admin)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100

---

### Option B: Full Stack with Honeypots

Deploy both monitoring and honeypot infrastructure for advanced threat intelligence.

#### 1. Deploy Main Stack (First Raspberry Pi)

```bash
git clone https://github.com/garrigueta/network-security-monitor.git
cd network-security-monitor/monitoring
docker-compose up -d
```

#### 2. Configure Second Raspberry Pi for Honeypots

**⚠️ IMPORTANT**: Change your real SSH port FIRST to avoid lockout:

```bash
# On second Raspberry Pi
sudo nano /etc/ssh/sshd_config
# Change Port 22 to Port 2222
sudo systemctl restart sshd

# Reconnect using new port
ssh -p 2222 user@honeypot-pi-ip
```

#### 3. Deploy Honeypot Stack (Second Device)

```bash
# On second Raspberry Pi
cd network-security-monitor/honeypot

# Configure environment
cp .env.example .env
nano .env
# Set LOKI_URL=http://MAIN-PI-IP:3100

# Deploy honeypots
docker-compose up -d
```

#### 4. Configure Router Port Forwarding

Forward these ports from the Internet to your honeypot Raspberry Pi:

| Service | External Port | Internal Port | Protocol |
|---------|---------------|---------------|----------|
| SSH Honeypot | 22 | 2222 | TCP |
| Telnet Honeypot | 23 | 2223 | TCP |
| FTP | 21 | 21 | TCP |
| SMB | 445 | 445 | TCP |
| MySQL | 3306 | 3306 | TCP |
| MSSQL | 1433 | 1433 | TCP |

#### 5. View Honeypot Attacks in Grafana

Access Grafana on your main Raspberry Pi and open the **Honeypot Attack Overview** dashboard.

**📖 Detailed honeypot documentation**: See [honeypot/README.md](honeypot/README.md)

---

## 📊 Service Details

### Grafana Dashboards

All dashboards are automatically provisioned on startup:

#### Network Security Monitoring
- **Zeek Security Overview**: Network security alerts and anomalies
- **Zeek Connection Analysis**: Network connection patterns and flows
- **Zeek DNS Security**: DNS queries and security analysis
- **Zeek SSL/TLS Analysis**: SSL/TLS certificate monitoring
- **Zeek Complete Analysis**: Comprehensive network analysis

#### System Monitoring
- **SSD I/O Monitoring**: Storage performance metrics
- **SSD Storage**: Disk usage statistics

#### Threat Intelligence (with honeypot)
- **Honeypot Attack Overview**: Real-time attack visualization
  - Attack distribution by honeypot type
  - SSH/Telnet attack counters
  - Malware connection tracking
  - Attack timeline and patterns
  - Login attempt logs
  - Top attack sources

#### Financial Monitoring
- **Crypto Prices**: Real-time cryptocurrency prices (Bitcoin, Ethereum, Tron)

### Metrics Endpoints

- **Prometheus**: `:9090`
- **Node Exporter**: `:9100/metrics`
- **Crypto Exporter**: `:9101/metrics`
- **Loki**: `:3100`
- **Promtail**: `:9080`

## 🛠️ Management Commands

### Main Stack Management

#### View Logs

```bash
cd monitoring

# All services
docker-compose logs -f

# Specific service
docker-compose logs -f zeek
docker-compose logs -f prometheus
docker-compose logs -f grafana
```

#### Restart Services

```bash
cd monitoring

# All services
docker-compose restart

# Specific service
docker-compose restart zeek
```

#### Stop Stack

```bash
cd monitoring
docker-compose down
```

#### Update Services

```bash
cd monitoring
docker-compose pull
docker-compose up -d
```

### Honeypot Management

```bash
cd honeypot

# Using Makefile
make start        # Start all honeypots
make stop         # Stop all honeypots
make restart      # Restart all honeypots
make logs         # View all logs
make status       # Check container status

# Manual commands
docker-compose up -d
docker-compose logs -f cowrie
docker-compose logs -f dionaea
docker-compose restart
```

### View Honeypot Attack Data

```bash
# SSH login attempts
docker-compose -f honeypot/docker-compose.yml exec cowrie tail -f /cowrie/cowrie-git/var/log/cowrie/cowrie.json

# Captured malware
docker-compose -f honeypot/docker-compose.yml exec cowrie ls -lh /cowrie/cowrie-git/var/lib/cowrie/downloads/

# Dionaea malware binaries
docker-compose -f honeypot/docker-compose.yml exec dionaea ls -lh /opt/dionaea/var/lib/dionaea/binaries/
```

## Data Persistence

Persistent volumes:
- `prometheus-data`: Prometheus metrics database
- `loki-data`: Loki log storage
- `grafana-data`: Grafana configuration and dashboards
- `zeek-logs`: Zeek log files
- `promtail-positions`: Promtail read positions

## 🔧 Troubleshooting

### Main Stack Issues

#### Zeek Not Capturing Traffic

1. Check network interface:
```bash
docker exec zeek ip link show
```

2. Verify interface in config:
```bash
docker exec zeek cat /usr/local/zeek/etc/node.cfg
```

3. Check Zeek status:
```bash
docker exec zeek zeekctl status
```

#### No Data in Grafana

1. Check Prometheus targets:
   - Go to http://localhost:9090/targets
   - All targets should show "UP"

2. Check Loki labels:
```bash
curl http://localhost:3100/loki/api/v1/labels
```

3. Verify Promtail is reading logs:
```bash
docker-compose logs promtail | grep "tail routine"
```

#### Crypto Prices Not Updating

1. Check exporter logs:
```bash
docker-compose logs crypto-exporter
```

2. Test metric endpoint:
```bash
curl http://localhost:9101/metrics | grep crypto_price_usd
```

### Honeypot Issues

#### Honeypot Not Receiving Connections

1. Verify port forwarding on router
2. Check firewall rules on honeypot device
3. Test external connectivity: `nmap -p 22,445,3306 YOUR-PUBLIC-IP`
4. Check container status: `cd honeypot && docker-compose ps`

#### Logs Not Appearing in Grafana

1. Verify Loki URL in honeypot `.env`: `cat honeypot/.env`
2. Test connectivity from honeypot to main Pi: `curl http://MAIN-PI-IP:3100/ready`
3. Check Promtail logs: `cd honeypot && docker-compose logs promtail`
4. Verify Loki is receiving data: `curl http://MAIN-PI-IP:3100/loki/api/v1/labels`

#### Can't SSH to Honeypot Device

If you get locked out after deploying honeypots:
- Connect via console (keyboard + monitor)
- Or access via another network interface if available
- Revert SSH port: `sudo nano /etc/ssh/sshd_config` (change back to 22)

---

## ⚙️ Customization

### Add More Cryptocurrencies

Edit `docker/crypto-exporter/crypto_exporter.py`:

```python
CRYPTO_IDS = ['bitcoin', 'ethereum', 'tron', 'cardano', 'solana']
```

Rebuild and restart:
```bash
docker-compose up -d --build crypto-exporter
```

### Custom Zeek Scripts

Add scripts to `docker/zeek/local.zeek`:

```zeek
@load custom/my-script
```

Rebuild and restart:
```bash
docker-compose up -d --build zeek
```

### Adjust Log Retention

Edit `docker/loki/loki-config.yml`:

```yaml
limits_config:
  retention_period: 168h  # Change to desired hours
```

Restart Loki:
```bash
docker-compose restart loki
```

## 🔒 Security Considerations

### Main Stack Security

1. **Change Default Passwords**: Update Grafana admin password immediately
2. **Network Isolation**: Use Docker networks to isolate services
3. **TLS/SSL**: Enable HTTPS for Grafana in production
4. **Access Control**: Use firewall rules to restrict access
5. **Volume Permissions**: Ensure proper permissions on mounted volumes
6. **Regular Updates**: Keep Docker images and system packages updated

### Honeypot Security ⚠️

**CRITICAL CONSIDERATIONS**:

1. **Isolate the Honeypot Device**:
   - Use a separate VLAN if possible
   - Ensure honeypot CANNOT access your internal network
   - Configure strict firewall rules blocking outbound connections to LAN
   - Only allow outbound to main monitoring Pi for log shipping

2. **Change Real SSH Port FIRST**:
   ```bash
   # BEFORE deploying honeypots
   sudo nano /etc/ssh/sshd_config
   Port 2222
   sudo systemctl restart sshd
   ```

3. **Malware Handling**:
   - Captured malware is EXTREMELY DANGEROUS
   - Never execute on production systems
   - Analyze only in isolated VMs
   - Follow proper malware analysis procedures

4. **Legal Considerations**:
   - Verify honeypot deployment is legal in your jurisdiction
   - Understand liability for attacks originating from your IP
   - Implement proper logging and retention policies
   - Have incident response procedures ready

5. **Resource Monitoring**:
   - Honeypots can be overwhelmed during attacks
   - Set Docker resource limits
   - Monitor CPU, memory, and bandwidth usage
   - Implement rate limiting if needed

## 💻 Resource Requirements

### Main Monitoring Stack

| Service | CPU | Memory | Storage |
|---------|-----|--------|---------|
| Zeek | 1-2 cores | 2GB | 10GB/day |
| Prometheus | 0.5-1 core | 1GB | 5GB/week |
| Loki | 0.5-1 core | 512MB | 5GB/week |
| Grafana | 0.25 core | 256MB | 1GB |
| Crypto Exporter | 0.1 core | 128MB | minimal |
| Node Exporter | 0.1 core | 64MB | minimal |
| **Total** | **3-5 cores** | **4GB+** | **100GB+** |

### Honeypot Stack (Second Device)

| Service | CPU | Memory | Storage |
|---------|-----|--------|---------|
| Cowrie | 0.5-1 core | 512MB | 5GB/month |
| Dionaea | 0.5 core | 256MB | 2GB/month |
| HoneyTrap | 0.25 core | 128MB | 1GB/month |
| Promtail | 0.25 core | 128MB | minimal |
| Node Exporter | 0.1 core | 64MB | minimal |
| **Total** | **2-3 cores** | **1-2GB** | **20GB+** |

## Backup and Restore

### Backup Volumes

```bash
# Stop services
docker-compose down

# Backup volumes
docker run --rm -v prometheus-data:/data -v $(pwd):/backup ubuntu tar czf /backup/prometheus-backup.tar.gz /data
docker run --rm -v loki-data:/data -v $(pwd):/backup ubuntu tar czf /backup/loki-backup.tar.gz /data
docker run --rm -v grafana-data:/data -v $(pwd):/backup ubuntu tar czf /backup/grafana-backup.tar.gz /data

# Start services
docker-compose up -d
```

### Restore Volumes

```bash
# Stop services
docker-compose down

# Restore volumes
docker run --rm -v prometheus-data:/data -v $(pwd):/backup ubuntu tar xzf /backup/prometheus-backup.tar.gz -C /
docker run --rm -v loki-data:/data -v $(pwd):/backup ubuntu tar xzf /backup/loki-backup.tar.gz -C /
docker run --rm -v grafana-data:/data -v $(pwd):/backup ubuntu tar xzf /backup/grafana-backup.tar.gz -C /

# Start services
docker-compose up -d
```

## 🎯 Use Cases

### Network Security Monitoring
- Monitor all network traffic on your local network
- Detect security threats and anomalies
- Analyze DNS queries for malicious domains
- Track SSL/TLS certificate usage
- Identify suspicious connection patterns

### Threat Intelligence Gathering
- Capture real-world attack patterns
- Collect malware samples for analysis
- Study brute-force attack techniques
- Analyze attacker behavior and tools
- Build blocklists from attacking IPs

### Cryptocurrency Tracking
- Monitor Bitcoin, Ethereum, and Tron prices
- Track price changes over time
- Set up alerts for price thresholds

### Home Lab Learning
- Learn Docker and container orchestration
- Study network security concepts
- Practice log analysis and correlation
- Understand attack methodologies
- Experiment with security tools

---

## 📚 Documentation

- **Main Overview**: This README (you are here)
- **Monitoring Stack Setup**: [monitoring/DOCKER-SETUP.md](monitoring/DOCKER-SETUP.md)
- **Honeypot Deployment**: [honeypot/README.md](honeypot/README.md)
- **Grafana Dashboards**: Pre-provisioned in `monitoring/grafana/dashboards/`
- **Loki Queries**: Examples in honeypot/README.md

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional Grafana dashboards
- More honeypot types
- Enhanced alerting rules
- GeoIP integration for attack mapping
- Automated threat intelligence feeds
- Additional cryptocurrency trackers

---

## 📝 License

This configuration is provided as-is for educational and network security monitoring purposes.

---

## 🙏 Acknowledgments

Built with:
- [Zeek](https://zeek.org/) - Network Security Monitor
- [Prometheus](https://prometheus.io/) - Metrics & Monitoring
- [Loki](https://grafana.com/oss/loki/) - Log Aggregation
- [Grafana](https://grafana.com/) - Visualization
- [Cowrie](https://github.com/cowrie/cowrie) - SSH Honeypot
- [Dionaea](https://github.com/DinoTools/dionaea) - Malware Honeypot
- [HoneyTrap](https://github.com/honeytrap/honeytrap) - Service Emulation

---

**Project**: Network Security Monitor  
**Repository**: https://github.com/garrigueta/network-security-monitor  
**Maintained by**: garrigueta
