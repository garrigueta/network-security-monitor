# Network Security AI Agent

AI-powered agent that provides intelligent analysis of your network security infrastructure using MCP (Model Context Protocol) and local LLM inference via Ollama.

## Features

- **MCP Server**: Structured access to monitoring data (Grafana, Loki, Prometheus)
- **FastAPI**: REST API for security analysis and queries
- **Ollama Integration**: Remote LLM inference for privacy and security
- **Multi-source Data**: Honeypot logs, network metrics, security alerts
- **Real-time Analysis**: Async data fetching and AI-powered insights

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