#!/bin/bash
# Raspberry Pi 5 Monitoring Stack Deployment Script
# Run this script on your Pi5 to set up the complete monitoring infrastructure

set -e

echo "=== Raspberry Pi 5 Network Security Monitoring Setup ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Please run this script as a regular user (not root)"
    exit 1
fi

# Step 1: System Update
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Step 2: Install Docker
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

# Step 3: Install Docker Compose
print_status "Installing Docker Compose..."
if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
    sudo apt install docker-compose-plugin -y
    print_status "Docker Compose installed successfully"
else
    print_status "Docker Compose already installed"
fi

# Step 4: Install additional tools
print_status "Installing Git and Make..."
sudo apt install git make -y

# Step 5: Clone repository
print_status "Cloning network security monitor repository..."
cd $HOME
if [ -d "network-security-monitor" ]; then
    print_warning "Repository already exists, pulling latest changes..."
    cd network-security-monitor
    git pull
else
    git clone https://github.com/garrigueta/network-security-monitor.git
    cd network-security-monitor
fi

# Step 6: Configure monitoring
print_status "Setting up monitoring configuration..."
cd monitoring

# Copy environment file
if [ ! -f ".env" ]; then
    cp .env.example .env
    print_status "Environment file created"
else
    print_warning "Environment file already exists"
fi

# Step 7: Detect network interface
print_status "Detecting network interfaces..."
echo "Available network interfaces:"
ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | grep -v "docker"

print_warning "Please note the interface you want to monitor (usually eth0 for Ethernet or wlan0 for WiFi)"
echo ""
read -p "Enter the network interface to monitor (default: eth0): " INTERFACE
INTERFACE=${INTERFACE:-eth0}

# Update environment file
sed -i "s/ZEEK_INTERFACE=.*/ZEEK_INTERFACE=$INTERFACE/" .env
print_status "Updated Zeek interface to: $INTERFACE"

# Step 8: Apply Docker group changes
print_status "Applying Docker group changes..."
newgrp docker << EONG
    # Step 9: Build and deploy
    print_status "Building and deploying monitoring stack..."
    make build
    make up
    
    # Step 10: Wait for services to start
    print_status "Waiting for services to initialize..."
    sleep 30
    
    # Step 11: Check service status
    print_status "Checking service status..."
    make status
EONG

echo ""
print_status "=== Deployment Complete! ==="
echo ""
echo "Access your monitoring services:"
echo "  • Grafana Dashboard: http://$(hostname -I | awk '{print $1}'):3000"
echo "    Username: admin"
echo "    Password: admin"
echo ""
echo "  • Prometheus: http://$(hostname -I | awk '{print $1}'):9090"
echo "  • Loki: http://$(hostname -I | awk '{print $1}'):3100"
echo ""
echo "Useful commands:"
echo "  • Check status: cd ~/network-security-monitor/monitoring && make status"
echo "  • View logs: cd ~/network-security-monitor/monitoring && make logs"
echo "  • Restart services: cd ~/network-security-monitor/monitoring && make restart"
echo "  • Stop services: cd ~/network-security-monitor/monitoring && make down"
echo ""
print_warning "Note: You may need to log out and back in for Docker group changes to take effect"
print_warning "If services don't start properly, try: cd ~/network-security-monitor/monitoring && make restart"