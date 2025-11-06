# Network Security Monitor

A comprehensive security monitoring platform designed to detect, analyze,
and respond to network threats through automated intelligence gathering
and real-time analysis.

## Overview

This project provides an end-to-end network security monitoring solution
that combines passive traffic analysis, active threat detection through
honeypots, and AI-powered security intelligence. The system continuously
monitors your network perimeter, captures attack attempts, and generates
actionable security reports.

**Key capabilities:**

- Deep packet inspection of all network traffic using Zeek
- Deception-based threat detection with multi-protocol honeypots
- AI-driven threat analysis and automated report generation
- Centralized log aggregation and metrics collection
- Pre-built security dashboards for instant visibility
- RESTful API for integration with other security tools

**Use cases:**

- Network perimeter monitoring and threat detection
- Attack pattern analysis and threat intelligence gathering
- Security operations center (SOC) data aggregation
- Incident response and forensic analysis
- Compliance monitoring and audit trail generation

## 📖 Documentation

**Complete documentation is available at: https://garrigueta.github.io/network-security-monitor-docs/**

The documentation includes:
- Installation guides and quick start
- Component architecture overview  
- Configuration and customization
- API reference with examples
- Dashboard guides and troubleshooting

## How It Works

The platform operates in three integrated layers:

**1. Data Collection Layer**
- Zeek monitors network traffic on a dedicated interface, generating logs
  for connections, DNS queries, HTTP requests, SSL/TLS handshakes, and more
- Heralding honeypot simulates SSH, Telnet, FTP, and HTTP services to
  attract and log unauthorized access attempts
- System metrics from Node Exporter track infrastructure health

**2. Storage and Processing Layer**
- Promtail agents tail logs from Zeek and honeypots, forwarding to Loki
- Prometheus scrapes metrics from all exporters for time-series analysis
- All logs and metrics persist to SSD storage for fast querying

**3. Analysis and Visualization Layer**
- Grafana dashboards provide real-time views of security events, network
  patterns, and system health
- AI Agent (OpenAI-powered) analyzes aggregated logs to identify threats,
  generate security reports, and provide natural language insights
- Scheduled reports run every 5 hours, with on-demand API access available

## Components

The platform consists of nine integrated services:

- **Zeek** - Network traffic analyzer capturing detailed protocol logs
- **Heralding** - Multi-protocol honeypot (SSH, Telnet, FTP, HTTP)
- **Grafana** - Visualization platform with 10 pre-built dashboards
- **Prometheus** - Metrics collection and time-series database
- **Loki** - Log aggregation system for centralized log storage
- **Promtail** - Log shipping agent for Zeek and honeypot logs
- **AI Agent** - OpenAI-powered threat analysis and report generation
- **Node Exporter** - System and hardware metrics exporter
- **Crypto Exporter** - Cryptocurrency price tracking (optional)

## Installation

### Prerequisites

- Kubernetes cluster (k3s v1.21+ or similar)
- Helm 3.x
- Docker for building custom images
- Dedicated network interface for Zeek to monitor
- Persistent storage (SSD recommended for better performance)

### Quick Start

Deploy the entire stack:

```bash
make all
```

This will build all container images and deploy the Helm chart.

### Manual Installation

Build images:

```bash
make images
```

Deploy to Kubernetes:

```bash
helm install nsm ./helm-chart/network-security-monitor \
  --namespace network-security \
  --create-namespace
```

### Finding Your Node IP

To access the web interfaces, you'll need your Kubernetes node IP:

```bash
kubectl get nodes -o wide
```

Or check the service endpoints:

```bash
kubectl get svc -n network-security
```



## Usage

### Grafana Dashboards

Access Grafana at `http://<NODE_IP>:3000` (default credentials: admin/admin)

Available dashboards:
- **Zeek Security Overview** - Network traffic patterns and threats
- **Zeek Connection Analysis** - Detailed connection tracking
- **Zeek DNS Security Analysis** - DNS query monitoring
- **Zeek SSL/TLS Analysis** - Certificate and encryption analysis
- **Honeypot Attack Overview** - Brute force and intrusion attempts
- **AI Security Reports** - Automated threat intelligence
- **SSD I/O Monitoring** - Storage performance metrics
- **SSD Storage Monitoring** - Disk usage and capacity

### AI Agent API

The AI Agent provides a RESTful API at `http://<NODE_IP>:8080`

Generate a security report:

```bash
curl -X POST http://<NODE_IP>:8080/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"report_type": "security", "time_range": "24h"}'
```

List all reports:

```bash
curl http://<NODE_IP>:8080/reports
```

Get latest report:

```bash
curl http://<NODE_IP>:8080/reports/latest
```

Query with natural language:

```bash
curl -X POST http://<NODE_IP>:8080/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the top attack sources in the last hour?"}'
```

See `ai-agent/API-DOCS.md` for complete API documentation.

## Configuration

### Network Interface

Set the interface for Zeek to monitor in the Helm values:

```yaml
# helm-chart/network-security-monitor/values.yaml
zeek:
  interface: eth1  # Change to your network interface
```

### Grafana Credentials

Change the default admin password:

```yaml
monitoring:
  grafana:
    adminPassword: your-secure-password
```

### Storage

The platform uses persistent volumes for all data. Default storage
allocation (configurable in `storage.yaml`):

```
/mnt/ssd-logs/           # Default base path
├── prometheus-data/     # Metrics time-series data (default: 20Gi)
├── loki-data/           # Centralized log storage (default: 20Gi)
├── grafana-data/        # Dashboard configurations (default: 5Gi)
├── zeek-logs/           # Network traffic logs (default: 30Gi)
└── honeypot-logs/       # Attack attempt logs (default: 10Gi)
```

**Total default allocation: ~85Gi**

Adjust storage sizes based on your environment in
`helm-chart/network-security-monitor/templates/storage.yaml`. For
high-traffic networks, increase Zeek and Loki storage accordingly.

To use a different storage path, update the `hostPath` values in the
PersistentVolume definitions.

### Dashboard Editing

Dashboards can be edited directly in Grafana and will auto-save to
`helm-chart/dashboards/` in your local repository.

## Management Commands

The included Makefile provides convenient shortcuts:

```bash
make status         # Check deployment status
make logs POD=name  # View logs for specific pod
make restart-grafana # Restart Grafana pod
make restart-promtail # Restart Promtail pod
make uninstall      # Remove the deployment
make clean          # Clean up all resources
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -n network-security
```

All pods should show `1/1 Running`.

### View Logs

```bash
kubectl logs -n network-security <pod-name>
```

Or use the Makefile:

```bash
make logs POD=ai-agent
```

### Common Issues

**Dashboards show no data:**
- Verify Promtail is running and tailing logs
- Check that Zeek is generating logs to the correct path
- Ensure datasource UIDs match in dashboard JSON files

**Grafana permission errors:**
```bash
sudo chown -R 472:472 /mnt/ssd-logs/grafana-data
```

**AI Agent reports not generating:**
- Verify OpenAI API key is configured
- Check that Loki has data: `kubectl logs -n network-security loki-0`
- Trigger manual report: `curl -X POST http://<NODE_IP>:8080/reports/generate`

## Documentation

- ai-agent/API-DOCS.md - API reference
- ai-agent/REPORTS.md - Report documentation
- monitoring/README.md - Monitoring stack details
- honeypot/README.md - Honeypot configuration

## License

[Specify license]
