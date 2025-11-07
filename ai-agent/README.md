# Network Security AI Agent

AI-powered agent that provides intelligent analysis of your network security infrastructure using MCP (Model Context Protocol) and local LLM inference via Ollama.

## Features

- **MCP Server**: Structured access to monitoring data (Grafana, Loki, Prometheus)
- **FastAPI**: REST API for security analysis and queries
- **Ollama Integration**: Remote LLM inference for privacy and security
- **Multi-source Data**: Honeypot logs, network metrics, security alerts
- **Real-time Analysis**: Async data fetching and AI-powered insights
- **Enhanced Zeek Log Parsing**: Comprehensive parsing of 11+ Zeek log types with proper field mapping
- **Advanced Analysis**: Automated detection of suspicious patterns, threats, and anomalies

## Quick Start

1. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your Ollama host and monitoring infrastructure IPs
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the AI agent**:
   ```bash
   python -m ai_agent.main
   ```

4. **Test the API**:
   ```bash
   curl http://localhost:8080/health
   ```

## API Endpoints

- `GET /health` - Service health check
- `POST /analyze/honeypot` - AI analysis of honeypot threats
- `POST /analyze/network` - Network security assessment  
- `POST /query` - Natural language security queries
- `GET /mcp/tools` - Available data access tools

## Enhanced Data Scraping Capabilities

The AI agent now includes advanced data scraping and analysis for Zeek network logs:

### Supported Zeek Log Types

The agent parses and analyzes 11 different Zeek log types:
- **conn**: Network connections (TCP, UDP, ICMP)
- **dns**: DNS queries and responses
- **http**: HTTP requests and responses
- **ssl**: SSL/TLS handshakes and certificates
- **ssh**: SSH connections
- **files**: File transfers over various protocols
- **weird**: Unusual network activity
- **notice**: Zeek notices and alerts
- **software**: Detected software and versions
- **x509**: X.509 certificate details
- **pe**: Portable Executable (PE) file analysis

### Advanced Analysis Features

#### Connection Analysis
```python
# Analyze network connection patterns
from ai_agent.data_sources import DataCollector

collector = DataCollector()
analysis = await collector.analyze_zeek_connections(hours=24)

# Returns:
# - Total connections, protocols, services
# - Top source/destination IPs
# - Connection duration and bytes transferred stats
# - Suspicious patterns (long-duration, large transfers)
```

#### DNS Analysis
```python
# Analyze DNS query patterns
dns_analysis = await collector.analyze_zeek_dns(hours=24)

# Returns:
# - Total queries, query types, response codes
# - Top queried domains
# - Failed queries
# - Suspicious domains (unusually long, many subdomains)
```

#### HTTP Analysis
```python
# Analyze web traffic patterns
http_analysis = await collector.analyze_zeek_http(hours=24)

# Returns:
# - HTTP methods, status codes, user agents
# - Top hosts and URIs
# - File downloads by MIME type
# - Suspicious requests (potential SQLi, XSS)
```

#### File Transfer Analysis
```python
# Analyze file transfers
file_analysis = await collector.analyze_zeek_files(hours=24)

# Returns:
# - Total files, MIME types, sources
# - File size statistics
# - Large files (>10MB)
# - Executable file transfers
```

### MCP Tools

New MCP tools available for AI-powered analysis:

- `analyze_zeek_connections` - Network connection pattern analysis
- `analyze_zeek_dns` - DNS query pattern and anomaly detection
- `analyze_zeek_http` - HTTP traffic and security threat analysis
- `analyze_zeek_files` - File transfer analysis
- `get_zeek_logs` - Raw Zeek log retrieval with proper parsing

### Example Usage

See `examples/zeek_analysis_demo.py` for a complete demonstration of the enhanced capabilities.

## Configuration

Edit `.env` file:
- `OLLAMA_HOST` - Your remote Ollama server IP
- `MONITORING_HOST` - Your monitoring stack IP (Grafana/Loki/Prometheus)
- `API_PORT` - AI agent API port (default: 8080)

## Testing

Run the test suite:
```bash
python3 tests/test_zeek_parsing.py
```

## Docker Deployment

```bash
docker-compose up -d
```

The AI agent connects to your existing monitoring infrastructure and remote Ollama server to provide intelligent security analysis.