# Monitoring Stack - Setup Guide

Complete Docker-based network security monitoring infrastructure for Raspberry Pi.

## Services Included

- **Zeek** - Network security monitoring and packet analysis
- **Prometheus** - Metrics collection and time-series database
- **Loki** - Log aggregation system
- **Promtail** - Log shipper for Zeek logs
- **Grafana** - Visualization and dashboards
- **Node Exporter** - System metrics collector
- **Crypto Exporter** - Cryptocurrency price tracking

## Quick Start

### Option 1: One Command Setup (Recommended)

```bash
make setup
```

### Option 2: Manual Setup

```bash
# Start services
docker compose up -d

# Fix dashboards (first time only)
./fix-dashboards.sh
```

### Access

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100

Set your network interface:
```bash
ZEEK_INTERFACE=eth1  # Change to your monitoring interface
```

### 3. Deploy

```bash
docker-compose up -d
```

### 4. Verify

```bash
docker-compose ps
docker-compose logs -f
```

### Using Makefile

```bash
make up      # Start services
make status  # Check health
make logs    # View logs
make down    # Stop services
```

## Access Points

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100

## Grafana Dashboards

Pre-configured dashboards automatically loaded:

- **Zeek Security Overview** - Network alerts and anomalies
- **Zeek Connection Analysis** - Network flows and patterns
- **Zeek DNS Security** - DNS queries and threats
- **Zeek SSL/TLS Analysis** - Certificate monitoring
- **Zeek Complete Analysis** - Comprehensive network analysis
- **Crypto Prices** - Bitcoin, Ethereum, Tron prices
- **SSD I/O & Storage** - System metrics
- **Honeypot Attack Overview** - Attack visualization (if honeypot deployed)

## Requirements

- Raspberry Pi 3B+, 4, or 5
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 100GB+ storage (SSD recommended)

## Troubleshooting

### Zeek Not Capturing Traffic

```bash
# Check interface
docker exec zeek ip link show

# Verify Zeek status
docker exec zeek zeekctl status

# Check logs
docker-compose logs zeek
```

### No Data in Grafana

```bash
# Check Prometheus targets
open http://localhost:9090/targets

# Verify Loki
curl http://localhost:3100/loki/api/v1/labels

# Check Promtail
docker-compose logs promtail | grep "tail routine"
```

### Crypto Prices Not Updating

```bash
# Check exporter logs
docker-compose logs crypto-exporter

# Test endpoint
curl http://localhost:9101/metrics | grep crypto_price_usd
```

## Customization

### Add Cryptocurrencies

Edit `crypto-exporter/crypto_exporter.py`:
```python
CRYPTO_IDS = ['bitcoin', 'ethereum', 'tron', 'cardano']
```

Rebuild:
```bash
docker-compose up -d --build crypto-exporter
```

### Custom Zeek Scripts

Edit `zeek/local.zeek` and rebuild:
```bash
docker-compose up -d --build zeek
```

### Log Retention

Edit `loki/loki-config.yml`:
```yaml
limits_config:
  retention_period: 168h
```

## Backup & Restore

### Backup

```bash
make backup
# Or manually:
docker run --rm -v prometheus-data:/data -v $(pwd):/backup \
  ubuntu tar czf /backup/prometheus.tar.gz /data
```

### Restore

```bash
docker-compose down
docker run --rm -v prometheus-data:/data -v $(pwd):/backup \
  ubuntu tar xzf /backup/prometheus.tar.gz -C /
docker-compose up -d
```

## Management

```bash
# Start/stop
docker-compose up -d
docker-compose down

# View logs
docker-compose logs -f
docker-compose logs -f zeek

# Restart service
docker-compose restart zeek

# Update images
docker-compose pull
docker-compose up -d
```

## Resource Usage

| Service | CPU | Memory | Storage |
|---------|-----|--------|---------|
| Zeek | 1-2 cores | 2GB | 10GB/day |
| Prometheus | 0.5-1 core | 1GB | 5GB/week |
| Loki | 0.5-1 core | 512MB | 5GB/week |
| Grafana | 0.25 core | 256MB | 1GB |

## Support

- Check logs: `docker-compose logs [service]`
- Main docs: [../README.md](../README.md)
- Honeypot: [../honeypot/README.md](../honeypot/README.md)
