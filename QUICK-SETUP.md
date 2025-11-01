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

3. **Follow the prompts** and wait for deployment to complete.

## Option 2: Manual Setup

### Prerequisites
```bash
# SSH to your Pi5
ssh pi@<your-pi-ip>

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker pi

# Install Docker Compose and tools
sudo apt install docker-compose-plugin git make -y

# Logout and login again (or run: newgrp docker)
```

### Deploy Monitoring Stack
```bash
# Clone repository
cd ~
git clone https://github.com/garrigueta/network-security-monitor.git
cd network-security-monitor/monitoring

# Configure environment
cp .env.example .env

# Check your network interface
ip link show

# Edit .env file and set correct interface
nano .env
# Change: ZEEK_INTERFACE=eth0  (or wlan0 for WiFi)

# Deploy the stack
make up

# Check status
make status
```

## Access Your Monitoring Dashboard

Once deployed, open your browser and go to:
- **Grafana**: `http://<your-pi-ip>:3000` (admin/admin)

## Troubleshooting

If you encounter issues:

1. **Check Docker is running**:
   ```bash
   sudo systemctl status docker
   ```

2. **Restart services**:
   ```bash
   cd ~/network-security-monitor/monitoring
   make restart
   ```

3. **View logs**:
   ```bash
   make logs
   ```

4. **Check system resources**:
   ```bash
   free -h
   df -h
   docker stats
   ```

## What Gets Installed

- **Zeek**: Network security monitoring
- **Prometheus**: Metrics collection  
- **Grafana**: Dashboards and visualization
- **Loki**: Log aggregation
- **Node Exporter**: System metrics
- **Crypto Exporter**: Cryptocurrency prices

All services run in Docker containers and will automatically restart on reboot.