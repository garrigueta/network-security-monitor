# Network Security AI Agent

AI-powered agent that provides intelligent analysis of your network security infrastructure using MCP (Model Context Protocol) and local LLM inference via Ollama.

## Features

### Core Capabilities
- **MCP Server**: Structured access to monitoring data (Grafana, Loki, Prometheus)
- **FastAPI**: REST API for security analysis and queries
- **Ollama Integration**: Remote LLM inference for privacy and security
- **Multi-source Data**: Honeypot logs, network metrics, security alerts
- **Real-time Analysis**: Async data fetching and AI-powered insights

### Advanced Capabilities
- **Threat Hunting**: IOC discovery, attack chain reconstruction, and evidence-based hunting
- **Event Correlation**: Cross-source correlation analysis, IP-based tracking, temporal pattern detection
- **Batch Processing**: Efficient batch analysis of multiple queries with controlled concurrency
- **Performance Optimization**: Response caching (5-min TTL), parallel data fetching, connection pooling
- **Resilient Operations**: Retry logic with exponential backoff, graceful degradation

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

### Basic Analysis
- `GET /health` - Service health check
- `POST /analyze/honeypot` - AI analysis of honeypot threats
- `POST /analyze/network` - Network security assessment  
- `POST /query` - Natural language security queries
- `GET /mcp/tools` - Available data access tools

### Advanced Analysis
- `POST /threat-hunt` - Advanced threat hunting with IOC tracking
- `POST /correlate` - Cross-source event correlation analysis
- `POST /batch-analyze` - Batch processing of multiple queries
- `GET /data-sources/summary` - Summary statistics from all data sources

### Report Management
- `POST /reports/generate` - Generate security reports
- `GET /reports` - List generated reports
- `GET /reports/latest/full` - Get latest full report
- `GET /reports/latest/analysis-html` - Get latest analysis as HTML

## Configuration

Edit `.env` file:
- `OLLAMA_HOST` - Your remote Ollama server IP
- `MONITORING_HOST` - Your monitoring stack IP (Grafana/Loki/Prometheus)
- `API_PORT` - AI agent API port (default: 8080)

## Docker Deployment

```bash
docker-compose up -d
```

The AI agent connects to your existing monitoring infrastructure and remote Ollama server to provide intelligent security analysis.

## Performance Features

- **Caching**: Responses cached for 5 minutes to reduce redundant AI queries
- **Parallel Processing**: Multiple data sources fetched simultaneously
- **Connection Pooling**: Optimized HTTP client with keep-alive connections
- **Retry Logic**: Exponential backoff for failed requests (3 attempts)
- **Batch Operations**: Process multiple queries efficiently with controlled concurrency