# Containerized Network Security Monitoring Stack

## What Was Created

A complete Docker-based infrastructure for network security monitoring has been created in the `docker/` directory.

## File Structure

```
docker/
├── docker-compose.yml                          # Main orchestration file
├── README.md                                   # Complete documentation
├── Makefile                                    # Helper commands
├── .env.example                                # Environment variables template
├── .gitignore                                  # Git ignore patterns
├── prometheus/
│   └── prometheus.yml                          # Metrics collection config
├── loki/
│   └── loki-config.yml                         # Log aggregation config
├── promtail/
│   └── promtail-config.yml                     # Log shipping config
├── zeek/
│   ├── Dockerfile                              # Zeek container build
│   ├── entrypoint.sh                           # Startup script
│   └── local.zeek                              # Zeek configuration
├── crypto-exporter/
│   ├── Dockerfile                              # Crypto exporter build
│   └── crypto_exporter.py                      # Python exporter
└── grafana/
    └── provisioning/
        ├── datasources/datasources.yml         # Auto-configure Prometheus/Loki
        └── dashboards/dashboards.yml           # Auto-load dashboards
```

## Quick Start

```bash
# Navigate to docker directory
cd docker/

# Copy environment template
cp .env.example .env

# Edit .env to set your network interface
nano .env

# Start the stack
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

Or use the Makefile:

```bash
cd docker/
make up      # Start services
make status  # Check health
make logs    # View logs
make down    # Stop services
```

## Access Points

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100

## Services Included

1. **Zeek** - Network security monitoring
2. **Prometheus** - Metrics collection
3. **Loki** - Log aggregation
4. **Promtail** - Log shipping
5. **Grafana** - Visualization
6. **Node Exporter** - System metrics
7. **Crypto Exporter** - Cryptocurrency prices

## Key Features

✅ Fully containerized - no host installation required
✅ Auto-configured datasources in Grafana
✅ Pre-loaded dashboards
✅ Persistent storage with Docker volumes
✅ Easy backup and restore
✅ Network isolation
✅ Automatic service restarts
✅ Production-ready configuration

## Important Notes

1. **Network Interface**: Change `ZEEK_INTERFACE` in `.env` to match your interface (default: eth1)
2. **Host Networking**: Zeek uses host networking mode for packet capture
3. **Permissions**: Zeek container needs NET_ADMIN and NET_RAW capabilities
4. **Storage**: Logs are stored in Docker volumes (survives container restarts)
5. **Dashboards**: All existing dashboards are automatically loaded

## Migration from Bare Metal

This setup replicates your current bare-metal installation:
- Same Prometheus configuration
- Same Loki/Promtail setup
- Same Zeek configuration
- All dashboards included
- Crypto exporter with same cryptocurrencies

## Next Steps

1. Review and customize `docker/.env`
2. Run `cd docker && docker-compose up -d`
3. Access Grafana at http://localhost:3000
4. Verify data is flowing in dashboards
5. Set up backups using `make backup`

## Documentation

Full documentation is available in `docker/README.md` including:
- Architecture overview
- Troubleshooting guide
- Customization options
- Production deployment tips
- Backup and restore procedures
- Resource requirements

## Support Commands

```bash
make help      # Show all available commands
make status    # Check service health
make backup    # Backup all data
make clean     # Complete cleanup
make update    # Update all images
```
