# Raspberry Pi 5 - Network Security Monitoring Setup

## Prerequisites

### 1. SSH Connection to Pi5
```bash
ssh pi@<your-pi-ip-address>
```

### 2. System Update
```bash
sudo apt update && sudo apt upgrade -y
```

### 3. Install Docker and Docker Compose
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker pi
newgrp docker

# Install Docker Compose
sudo apt install docker-compose-plugin -y

# Verify installation
docker --version
docker compose version
```

### 4. Install Git and Make
```bash
sudo apt install git make -y
```

## Setup Instructions

### Step 1: Clone Repository
```bash
cd ~
git clone https://github.com/garrigueta/network-security-monitor.git
cd network-security-monitor/monitoring
```

### Step 2: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

**Important Configuration Changes:**
- Set `ZEEK_INTERFACE` to your Pi's network interface (usually `eth0` or `wlan0`)
- Adjust memory limits for Pi5 if needed

### Step 3: Identify Network Interface
```bash
# List available network interfaces
ip link show

# Common interfaces:
# - eth0: Ethernet
# - wlan0: WiFi
# - docker0: Docker bridge (ignore)
```

### Step 4: Update Zeek Configuration
Edit the docker-compose.yml if needed:
```bash
nano docker-compose.yml
```

Change the `ZEEK_INTERFACE` environment variable to match your interface.

### Step 5: Deploy the Stack
```bash
# Option 1: Using Make (recommended)
make up

# Option 2: Using Docker Compose directly
docker compose up -d
```

### Step 6: Verify Deployment
```bash
# Check service status
make status

# View logs
make logs

# Check individual services
docker compose ps
```

## Access Points

Once deployed, access these services from your local network:

- **Grafana Dashboard**: http://&lt;pi-ip&gt;:3000 (admin/admin)
- **Prometheus**: http://&lt;pi-ip&gt;:9090
- **Loki**: http://&lt;pi-ip&gt;:3100

## Monitoring Capabilities

The stack provides:

1. **Network Security Monitoring** (Zeek)
   - Real-time packet analysis
   - Protocol detection
   - Security event logging

2. **System Metrics** (Node Exporter + Prometheus)
   - CPU, memory, disk usage
   - Network statistics
   - Temperature monitoring

3. **Log Aggregation** (Loki + Promtail)
   - Centralized log collection
   - Zeek log processing
   - Search and filtering

4. **Visualization** (Grafana)
   - Pre-built dashboards
   - Custom metrics visualization
   - Alerting capabilities

5. **Cryptocurrency Monitoring**
   - Bitcoin, Ethereum, Tron prices
   - Market trend analysis

## Troubleshooting

### Common Issues

1. **Zeek not capturing traffic**
   ```bash
   # Check interface permissions
   sudo docker exec zeek ip link show
   
   # Restart Zeek service
   docker compose restart zeek
   ```

2. **High memory usage**
   ```bash
   # Monitor resource usage
   docker stats
   
   # Adjust memory limits in .env file
   nano .env
   ```

3. **Port conflicts**
   ```bash
   # Check port usage
   sudo netstat -tulpn | grep :3000
   
   # Modify ports in docker-compose.yml if needed
   ```

### Performance Optimization for Pi5

1. **Use SSD storage** for better I/O performance
2. **Enable swap** if memory is limited:
   ```bash
   sudo dphys-swapfile swapoff
   sudo nano /etc/dphys-swapfile
   # Set CONF_SWAPSIZE=2048
   sudo dphys-swapfile setup
   sudo dphys-swapfile swapon
   ```

3. **Monitor temperature**:
   ```bash
   # Check temperature
   vcgencmd measure_temp
   
   # Ensure adequate cooling for sustained monitoring
   ```

## Maintenance Commands

```bash
# Update containers
docker compose pull
docker compose up -d

# Backup data
make backup

# Clean logs
docker system prune -f

# Restart all services
make restart

# View service logs
make logs-zeek        # Zeek logs
make logs-grafana     # Grafana logs
make logs-prometheus  # Prometheus logs
```

## Next Steps

1. **Configure Dashboards**: Customize Grafana dashboards for your specific monitoring needs
2. **Set Alerts**: Configure alerting rules in Grafana for security events
3. **Integrate Honeypot**: Deploy the honeypot stack for additional threat intelligence
4. **Network Segmentation**: Consider VLAN setup for isolated monitoring

## Security Considerations

- Change default Grafana credentials
- Configure firewall rules
- Enable HTTPS for external access
- Regular security updates
- Monitor access logs