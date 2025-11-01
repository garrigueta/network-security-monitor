#!/bin/bash
# Raspberry Pi 5 Network Security Monitoring Setup
# Single definitive setup script for Pi5 with dual NICs and SSD storage
# eth0: Management/Internet, eth1: Mirrored traffic monitoring

set -e

echo "=== Raspberry Pi 5 Network Security Monitor Setup ==="
echo "Configuration:"
echo "  • eth0: Regular switch port (management/internet)"
echo "  • eth1: Mirrored traffic port (network monitoring)"
echo "  • SSD: External USB storage for logs and data"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Please run this script as a regular user (not root)"
    exit 1
fi

# Step 1: Fix hostname resolution
print_status "Fixing hostname resolution..."
if ! grep -q "$(hostname)" /etc/hosts; then
    echo "127.0.1.1 $(hostname)" | sudo tee -a /etc/hosts > /dev/null
    print_status "Added hostname to /etc/hosts"
fi

# Step 2: Verify network interfaces
print_status "Verifying network configuration..."
if ! ip link show eth1 &> /dev/null; then
    print_error "eth1 interface not found! Please ensure dual NICs are configured"
    exit 1
fi

print_status "Network interfaces:"
echo "  • eth0: $(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | head -1 || echo 'No IP')"
echo "  • eth1: $(ip link show eth1 | grep 'state' | awk '{print $9}' || echo 'Unknown state')"

# Step 3: Setup SSD storage
print_status "Setting up SSD storage..."
echo "Available storage devices:"
lsblk | grep -E "(sd|nvme)" | head -10

# Auto-detect likely SSD device
SSD_CANDIDATES=$(lsblk -d -o NAME,SIZE,MODEL | grep -E "(sd[a-z]|nvme)" | grep -v "$(lsblk | grep '/$' | awk '{print substr($1,3,3)}')" || true)

if [ -n "$SSD_CANDIDATES" ]; then
    echo "Detected external storage devices:"
    echo "$SSD_CANDIDATES"
    echo ""
    
    FIRST_DEVICE=$(echo "$SSD_CANDIDATES" | head -1 | awk '{print $1}')
    AUTO_SSD="/dev/${FIRST_DEVICE}1"
    
    read -p "Use detected SSD device ${AUTO_SSD}? [Y/n]: " USE_AUTO
    if [[ "$USE_AUTO" =~ ^[Nn] ]]; then
        read -p "Enter the SSD device path (e.g., /dev/sda1): " SSD_DEVICE
    else
        SSD_DEVICE="$AUTO_SSD"
    fi
else
    read -p "Enter the SSD device path (e.g., /dev/sda1): " SSD_DEVICE
fi

if [ ! -b "$SSD_DEVICE" ]; then
    print_error "Device $SSD_DEVICE not found!"
    exit 1
fi

# Mount SSD
if ! mountpoint -q /mnt/ssd-logs; then
    sudo mkdir -p /mnt/ssd-logs
    sudo mount $SSD_DEVICE /mnt/ssd-logs
    sudo chown -R $USER:$USER /mnt/ssd-logs
    
    if ! grep -q "$SSD_DEVICE" /etc/fstab; then
        echo "$SSD_DEVICE /mnt/ssd-logs ext4 defaults 0 2" | sudo tee -a /etc/fstab
    fi
    
    print_status "SSD mounted at /mnt/ssd-logs"
else
    print_status "SSD already mounted"
fi

# Create directory structure with proper ownership
sudo mkdir -p /mnt/ssd-logs/{zeek-logs/logs,zeek-logs/spool,prometheus-data,loki-data,grafana-data,promtail-positions}

# Set ownership for each service (matching Docker user IDs)
sudo chown -R 472:472 /mnt/ssd-logs/grafana-data      # Grafana
sudo chown -R 65534:65534 /mnt/ssd-logs/prometheus-data # Prometheus  
sudo chown -R 10001:10001 /mnt/ssd-logs/loki-data     # Loki
sudo chown -R $USER:$USER /mnt/ssd-logs/zeek-logs     # Zeek (including logs and spool subdirs)
sudo chown -R $USER:$USER /mnt/ssd-logs/promtail-positions # Promtail

# Step 4: System update and install packages
print_status "Updating system and installing packages..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y git make tcpdump

# Step 5: Install Docker
print_status "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    print_status "Docker installed successfully"
else
    print_status "Docker already installed"
fi

# Step 6: Install Docker Compose
print_status "Installing Docker Compose..."
sudo apt install -y docker-compose-plugin

# Step 7: Test mirrored traffic
print_status "Testing mirrored traffic on eth1..."
print_warning "Testing for 10 seconds - this should show mirrored network traffic"
timeout 10 sudo tcpdump -i eth1 -c 20 2>/dev/null | head -5 || print_warning "No traffic detected - verify switch mirror configuration"

# Step 8: Clone and setup repository
print_status "Setting up monitoring software..."
cd $HOME
if [ -d "network-security-monitor" ]; then
    cd network-security-monitor && git pull
else
    git clone https://github.com/garrigueta/network-security-monitor.git
    cd network-security-monitor
fi

cd monitoring

# Step 9: Configure environment
print_status "Configuring for Pi5 with SSD..."
cp .env.example .env
sed -i 's/ZEEK_INTERFACE=.*/ZEEK_INTERFACE=eth1/' .env

# Step 10: Deploy with Docker
print_status "Deploying monitoring stack..."
newgrp docker << 'EONG'
    make build
    make up
    sleep 30
    make status
EONG

echo ""
print_status "=== Deployment Complete! ==="
echo ""
echo "🔗 Access your monitoring services:"
echo "  • Grafana Dashboard: http://$(hostname -I | awk '{print $1}'):3000"
echo "    Username: admin / Password: admin"
echo ""
echo "  📊 Prometheus: http://$(hostname -I | awk '{print $1}'):9090"
echo "  📋 Loki: http://$(hostname -I | awk '{print $1}'):3100"
echo ""
echo "💾 Data storage: /mnt/ssd-logs ($(df -h /mnt/ssd-logs | tail -1 | awk '{print $4}') available)"
echo ""
echo "🔧 Useful commands:"
echo "  • Check status: cd ~/network-security-monitor/monitoring && make status"
echo "  • View logs: make logs"
echo "  • Monitor resources: docker stats"
echo "  • Check SSD usage: df -h /mnt/ssd-logs"
echo ""
print_warning "Reboot recommended to ensure all services start properly on boot"