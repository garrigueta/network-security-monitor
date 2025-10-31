# Network Security Monitoring Stack - Docker Deployment

Complete containerized infrastructure for network security monitoring using Zeek, Prometheus, Loki, and Grafana.

## Architecture

This stack includes:
- **Zeek**: Network Security Monitor for packet analysis
- **Prometheus**: Metrics collection and time-series database
- **Loki**: Log aggregation system
- **Promtail**: Log shipper for Zeek logs to Loki
- **Grafana**: Visualization and dashboards
- **Node Exporter**: System metrics collector
- **Crypto Exporter**: Cryptocurrency price metrics

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Network interface for Zeek to monitor (default: eth1)
- Minimum 4GB RAM
- Minimum 20GB disk space

## Directory Structure

```
docker/
├── docker-compose.yml          # Main orchestration file
├── prometheus/
│   └── prometheus.yml          # Prometheus configuration
├── loki/
│   └── loki-config.yml         # Loki configuration
├── promtail/
│   └── promtail-config.yml     # Promtail configuration
├── zeek/
│   ├── Dockerfile              # Zeek container build
│   ├── entrypoint.sh           # Zeek startup script
│   └── local.zeek              # Zeek local configuration
├── crypto-exporter/
│   ├── Dockerfile              # Crypto exporter build
│   └── crypto_exporter.py      # Python exporter script
└── grafana/
    └── provisioning/
        ├── datasources/        # Auto-configure data sources
        └── dashboards/         # Auto-load dashboards
```

## Quick Start

### 1. Configuration

Edit `docker-compose.yml` to set your network interface:

```yaml
services:
  zeek:
    environment:
      - ZEEK_INTERFACE=eth1  # Change to your interface
```

### 2. Deploy the Stack

```bash
cd docker
docker-compose up -d
```

### 3. Verify Services

Check all services are running:

```bash
docker-compose ps
```

Expected output:
```
NAME                IMAGE                        STATUS
crypto-exporter     crypto-exporter             Up
grafana             grafana/grafana:latest      Up
loki                grafana/loki:latest         Up
node-exporter       prom/node-exporter:latest   Up
prometheus          prom/prometheus:latest      Up
promtail            grafana/promtail:latest     Up
zeek                zeek                        Up
```

### 4. Access the Services

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100

## Service Details

### Grafana Dashboards

Pre-configured dashboards:
- **Crypto Prices**: Real-time cryptocurrency prices (Bitcoin, Ethereum, Tron)
- **Zeek Security Overview**: Network security alerts and anomalies
- **Zeek Connection Analysis**: Network connection patterns
- **Zeek DNS Security**: DNS queries and security analysis
- **Zeek SSL/TLS Analysis**: SSL/TLS certificate monitoring
- **Zeek Complete Analysis**: Comprehensive network analysis
- **SSD I/O Monitoring**: Storage performance metrics
- **SSD Storage**: Disk usage statistics

### Metrics Endpoints

- **Prometheus**: `:9090`
- **Node Exporter**: `:9100/metrics`
- **Crypto Exporter**: `:9101/metrics`
- **Loki**: `:3100`
- **Promtail**: `:9080`

## Management Commands

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f zeek
docker-compose logs -f grafana
```

### Restart Services

```bash
# All services
docker-compose restart

# Specific service
docker-compose restart zeek
```

### Stop Stack

```bash
docker-compose down
```

### Stop and Remove Volumes (Clean Reset)

```bash
docker-compose down -v
```

### Update Services

```bash
docker-compose pull
docker-compose up -d
```

## Data Persistence

Persistent volumes:
- `prometheus-data`: Prometheus metrics database
- `loki-data`: Loki log storage
- `grafana-data`: Grafana configuration and dashboards
- `zeek-logs`: Zeek log files
- `promtail-positions`: Promtail read positions

## Troubleshooting

### Zeek Not Capturing Traffic

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

### No Data in Grafana

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

### Crypto Prices Not Updating

1. Check exporter logs:
```bash
docker-compose logs crypto-exporter
```

2. Test metric endpoint:
```bash
curl http://localhost:9101/metrics | grep crypto_price_usd
```

## Customization

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

## Security Considerations

1. **Change Default Passwords**: Update Grafana admin password
2. **Network Isolation**: Use Docker networks to isolate services
3. **TLS/SSL**: Enable HTTPS for Grafana in production
4. **Access Control**: Use firewall rules to restrict access
5. **Volume Permissions**: Ensure proper permissions on mounted volumes

## Resource Requirements

Recommended resources per service:

| Service | CPU | Memory | Storage |
|---------|-----|--------|---------|
| Zeek | 1-2 cores | 2GB | 10GB/day |
| Prometheus | 0.5-1 core | 1GB | 5GB/week |
| Loki | 0.5-1 core | 512MB | 5GB/week |
| Grafana | 0.25 core | 256MB | 1GB |
| Total | 3-5 cores | 4GB+ | 100GB+ |

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

## Production Deployment

For production use:

1. Use external storage for volumes (NFS, block storage)
2. Enable authentication for all services
3. Set up monitoring and alerting for the stack itself
4. Implement backup automation
5. Use container orchestration (Kubernetes, Docker Swarm)
6. Configure log rotation and retention policies
7. Set resource limits in docker-compose.yml

## Support

For issues and questions:
- Check logs: `docker-compose logs [service]`
- Review documentation in this README
- Verify network connectivity between containers

## License

This configuration is provided as-is for network security monitoring purposes.
