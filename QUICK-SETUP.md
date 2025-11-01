# Quick Setup Guide for Raspberry Pi 5

## Option 1: Automated Setup (Recommended)

1. **Copy the deployment script** to your Pi5:
   ```bash
   scp deploy-pi5.sh pi@<your-pi-ip>:~/
   ```

2. **SSH into your Pi5** and run the script:
   ```bash
   ssh pi@<your-pi-ip>
   chmod +x deploy-pi5.sh
   ./deploy-pi5.sh
   ```

3. **Follow the prompts** - the script will automatically:
   - Mount your USB SSD
   - Configure eth1 for mirrored traffic monitoring
   - Deploy the complete monitoring stack

## Option 2: Manual Setup

### Prerequisites
```bash
# SSH to your Pi5
ssh pi@<your-pi-ip>

# Fix hostname resolution (if needed)
echo "127.0.1.1 $(hostname)" | sudo tee -a /etc/hosts

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker pi

# Install Docker Compose and tools
sudo apt install docker-compose-plugin git make tcpdump -y

# Logout and login again (or run: newgrp docker)
```

### Mount USB SSD for Log Storage
```bash
# List available storage devices
lsblk

# Find your USB SSD (usually /dev/sda1 or /dev/sdb1)
sudo fdisk -l

# Create mount point
sudo mkdir -p /mnt/ssd-logs

# Mount the SSD (replace /dev/sda1 with your actual device)
sudo mount /dev/sda1 /mnt/ssd-logs

# Set proper ownership
sudo chown -R $USER:$USER /mnt/ssd-logs

# Add to fstab for persistent mounting
echo '/dev/sda1 /mnt/ssd-logs ext4 defaults 0 2' | sudo tee -a /etc/fstab

# Create directories for services
sudo mkdir -p /mnt/ssd-logs/{zeek-logs/logs,zeek-logs/spool,prometheus-data,loki-data,grafana-data,promtail-positions}

# Set correct ownership for each service (Docker user IDs)
sudo chown -R 472:472 /mnt/ssd-logs/grafana-data      # Grafana
sudo chown -R 65534:65534 /mnt/ssd-logs/prometheus-data # Prometheus  
sudo chown -R 10001:10001 /mnt/ssd-logs/loki-data     # Loki
sudo chown -R $USER:$USER /mnt/ssd-logs/zeek-logs     # Zeek
sudo chown -R $USER:$USER /mnt/ssd-logs/promtail-positions # Promtail

# Verify mount
df -h /mnt/ssd-logs
```

### Deploy Monitoring Stack
```bash
# Clone repository
cd ~
git clone https://github.com/garrigueta/network-security-monitor.git
cd network-security-monitor/monitoring

# Configure environment
cp .env.example .env

# Check your network interfaces
ip link show

# Verify dual NIC setup
# eth0: Regular switch port (management/internet)
# eth1: Mirrored traffic port (monitoring)

# Test mirrored traffic on eth1
sudo tcpdump -i eth1 -c 10

# Edit .env file and confirm interface setting
nano .env
# Should show: ZEEK_INTERFACE=eth1

# Deploy the stack
make up

# If make command fails, use docker compose directly:
# docker compose up -d

# Check status
make status

# If make status fails, use:
# docker compose ps
```

## Access Your Monitoring Dashboard

Once deployed, open your browser and go to:
- **Grafana**: `http://<your-pi-ip>:3000` (admin/admin)

## Troubleshooting

If you encounter issues:

1. **Services restarting (most common issue)**:
   ```bash
   # Check if SSD is mounted
   df -h /mnt/ssd-logs
   
   # If not mounted, mount it:
   sudo mount /dev/sda1 /mnt/ssd-logs
   
   # Fix directories and permissions
   sudo mkdir -p /mnt/ssd-logs/{zeek-logs/logs,zeek-logs/spool,prometheus-data,loki-data,grafana-data,promtail-positions}
   sudo chown -R 472:472 /mnt/ssd-logs/grafana-data
   sudo chown -R 65534:65534 /mnt/ssd-logs/prometheus-data
   sudo chown -R 10001:10001 /mnt/ssd-logs/loki-data
   sudo chown -R $USER:$USER /mnt/ssd-logs/zeek-logs
   sudo chown -R $USER:$USER /mnt/ssd-logs/promtail-positions
   
   # Restart services
   docker compose down
   docker compose up -d
   ```

2. **Check Docker is running**:
   ```bash
   sudo systemctl status docker
   ```

3. **View service logs**:
   ```bash
   docker compose logs grafana
   docker compose logs prometheus
   docker compose logs zeek
   docker compose logs loki
   ```

4. **Check system resources**:
   ```bash
   free -h
   df -h
   docker stats
   ```

5. **Network interface issues**:
   ```bash
   # Verify eth1 exists and is up
   ip link show eth1
   
   # Test for mirrored traffic
   sudo tcpdump -i eth1 -c 10
   ```

## What Gets Installed

- **Zeek**: Network security monitoring
- **Prometheus**: Metrics collection  
- **Grafana**: Dashboards and visualization
- **Loki**: Log aggregation
- **Node Exporter**: System metrics
- **Crypto Exporter**: Cryptocurrency prices

All services run in Docker containers and will automatically restart on reboot.