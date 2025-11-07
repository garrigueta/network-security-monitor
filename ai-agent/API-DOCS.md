# Network Security AI Agent API Documentation

## Overview

The Network Security AI Agent provides an intelligent REST API for analyzing network security data, honeypot activity, and system metrics. It integrates with your existing monitoring infrastructure to provide AI-powered insights and threat analysis.

## API Documentation

### Interactive Documentation

- **Swagger UI**: http://localhost:8080/docs
- **ReDoc**: http://localhost:8080/redoc
- **OpenAPI JSON**: http://localhost:8080/openapi.json
- **OpenAPI YAML**: http://localhost:8080/openapi.yaml

### Base URL

- Local Development: `http://localhost:8080`
- Production: `http://192.168.1.135:8080`

## Authentication

Most endpoints require API key authentication. Include your API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key-here" http://localhost:8080/analyze/honeypot
```

## Quick Start Examples

### 1. Health Check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "services": {
    "api": "running",
    "mcp_server": "running",
    "ai_engine": "running"
  }
}
```

### 2. Analyze Honeypot Activity

```bash
curl -X POST "http://localhost:8080/analyze/honeypot" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "period": "24h",
    "sources": ["cowrie", "dionaea"],
    "focus_areas": ["brute_force", "malware"]
  }'
```

### 3. Analyze Network Security

```bash
curl -X POST "http://localhost:8080/analyze/network" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "metrics": ["traffic", "security_events"],
    "timeframe": "1h",
    "focus": "threats"
  }'
```

### 4. Natural Language Query

```bash
curl -X POST "http://localhost:8080/query" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "query": "What are the most common attack patterns in the last 24 hours?"
  }'
```

### 5. List Available MCP Tools

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/mcp/tools
```

### 6. Threat Hunting

```bash
curl -X POST "http://localhost:8080/threat-hunt" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "hunt_focus": "lateral_movement",
    "time_range": "24h",
    "ioc_list": ["192.168.1.100", "malicious-domain.com"]
  }'
```

### 7. Event Correlation

```bash
curl -X POST "http://localhost:8080/correlate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "time_range": "24h",
    "correlation_type": "cross_source"
  }'
```

### 8. Batch Analysis

```bash
curl -X POST "http://localhost:8080/batch-analyze" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "queries": [
      {"type": "honeypot", "timeframe": "24h"},
      {"type": "network", "timeframe": "6h"},
      {"type": "threat_hunt", "hunt_focus": "data_exfiltration", "time_range": "24h"}
    ]
  }'
```

### 9. Data Sources Summary

```bash
curl "http://localhost:8080/data-sources/summary?hours=24" \
  -H "X-API-Key: your-api-key"
```

## Endpoints

### Basic Analysis
| Endpoint | Method | Description | Auth Required |
|----------|---------|-------------|---------------|
| `/health` | GET | Service health check | No |
| `/analyze/honeypot` | POST | Analyze honeypot activity | Yes |
| `/analyze/network` | POST | Analyze network security | Yes |
| `/query` | POST | Natural language queries | Yes |
| `/mcp/tools` | GET | List MCP tools | Yes |

### Advanced Analysis
| Endpoint | Method | Description | Auth Required |
|----------|---------|-------------|---------------|
| `/threat-hunt` | POST | Advanced threat hunting with IOC tracking | Yes |
| `/correlate` | POST | Cross-source event correlation | Yes |
| `/batch-analyze` | POST | Batch processing of multiple queries | Yes |
| `/data-sources/summary` | GET | Summary statistics from all sources | Yes |

### Documentation
| Endpoint | Method | Description | Auth Required |
|----------|---------|-------------|---------------|
| `/docs` | GET | Swagger UI documentation | No |
| `/redoc` | GET | ReDoc documentation | No |
| `/openapi.json` | GET | OpenAPI specification (JSON) | No |
| `/openapi.yaml` | GET | OpenAPI specification (YAML) | No |

## Response Formats

### Analysis Response

```json
{
  "success": true,
  "analysis": {
    "timestamp": "2025-11-01T23:03:08.906369",
    "timeframe": "24h",
    "ai_analysis": "AI-generated insights...",
    "raw_data": { ... },
    "focus_areas": ["general"]
  },
  "timestamp": "2025-11-01T23:03:08.906369",
  "metadata": { ... }
}
```

### Query Response

```json
{
  "success": true,
  "answer": "AI-generated answer to your question...",
  "timestamp": "2025-11-01T23:03:08.906369",
  "sources": ["honeypot_logs", "network_metrics"],
  "confidence": 0.85
}
```

### Threat Hunt Response

```json
{
  "success": true,
  "hunt_focus": "lateral_movement",
  "time_range": "24h",
  "ai_analysis": "Comprehensive threat hunting analysis...",
  "ioc_matches": {
    "192.168.1.100": 5,
    "malicious-domain.com": 12
  },
  "timestamp": "2025-11-01T23:03:08.906369",
  "metadata": {
    "data_sources": ["honeypot", "threat_patterns", "security_alerts"],
    "ioc_provided": true
  }
}
```

### Correlation Response

```json
{
  "success": true,
  "time_range": "24h",
  "correlation_type": "cross_source",
  "correlations_found": {
    "ip_correlations": {
      "192.168.1.50": {
        "count": 45,
        "event_types": ["ssh.login", "telnet.session"]
      }
    },
    "temporal_correlations": [
      {
        "type": "burst_activity",
        "event_count": 150,
        "description": "Detected burst of 150 events in 24h"
      }
    ],
    "pattern_matches": []
  },
  "ai_analysis": "Correlation analysis results...",
  "timestamp": "2025-11-01T23:03:08.906369",
  "metadata": {
    "sources_analyzed": ["honeypot", "alerts", "metrics"],
    "total_events": 250
  }
}
```

### Batch Analysis Response

```json
{
  "success": true,
  "results": [
    {
      "query_index": 0,
      "result": { ... },
      "success": true
    },
    {
      "query_index": 1,
      "result": { ... },
      "success": true
    }
  ],
  "total_queries": 3,
  "successful": 3,
  "failed": 0,
  "timestamp": "2025-11-01T23:03:08.906369"
}
```

### Data Sources Summary Response

```json
{
  "success": true,
  "summary": {
    "timestamp": "2025-11-01T23:03:08.906369",
    "timeframe_hours": 24,
    "honeypot": {
      "total_events": 1250,
      "unique_ips": 87
    },
    "alerts": {
      "total": 15
    },
    "zeek": {
      "log_types": ["conn", "dns", "http", "ssl"],
      "total_entries": 5420
    },
    "data_sources_available": [
      "honeypot_logs",
      "security_alerts",
      "threat_analysis",
      "zeek_logs",
      "metric_cpu_usage",
      "metric_memory_usage"
    ]
  },
  "timestamp": "2025-11-01T23:03:08.906369"
}
```

### Error Response

```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2025-11-01T23:03:08.906369"
}
```

## Client Libraries

### Python

```python
import requests

class SecurityAIClient:
    def __init__(self, base_url="http://localhost:8080", api_key=None):
        self.base_url = base_url
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["X-API-Key"] = api_key
    
    def health_check(self):
        response = requests.get(f"{self.base_url}/health")
        return response.json()
    
    def analyze_honeypot(self, period="24h", sources=None, focus_areas=None):
        data = {
            "period": period,
            "sources": sources or ["cowrie", "dionaea"],
            "focus_areas": focus_areas
        }
        response = requests.post(f"{self.base_url}/analyze/honeypot", 
                               json=data, headers=self.headers)
        return response.json()
    
    def query(self, question):
        data = {"query": question}
        response = requests.post(f"{self.base_url}/query", 
                               json=data, headers=self.headers)
        return response.json()
    
    def threat_hunt(self, hunt_focus, time_range="24h", ioc_list=None):
        data = {
            "hunt_focus": hunt_focus,
            "time_range": time_range,
            "ioc_list": ioc_list
        }
        response = requests.post(f"{self.base_url}/threat-hunt",
                               json=data, headers=self.headers)
        return response.json()
    
    def correlate_events(self, time_range="24h", correlation_type="cross_source"):
        data = {
            "time_range": time_range,
            "correlation_type": correlation_type
        }
        response = requests.post(f"{self.base_url}/correlate",
                               json=data, headers=self.headers)
        return response.json()
    
    def batch_analyze(self, queries):
        data = {"queries": queries}
        response = requests.post(f"{self.base_url}/batch-analyze",
                               json=data, headers=self.headers)
        return response.json()
    
    def get_data_summary(self, hours=24):
        response = requests.get(f"{self.base_url}/data-sources/summary?hours={hours}",
                              headers=self.headers)
        return response.json()

# Usage
client = SecurityAIClient(api_key="your-api-key")

# Basic analysis
result = client.analyze_honeypot(period="1h")

# Threat hunting
hunt_result = client.threat_hunt(
    hunt_focus="lateral_movement",
    time_range="24h",
    ioc_list=["192.168.1.100", "malicious.com"]
)

# Event correlation
correlation = client.correlate_events(time_range="24h")

# Batch processing
batch_result = client.batch_analyze([
    {"type": "honeypot", "timeframe": "24h"},
    {"type": "network", "timeframe": "6h"},
    {"type": "threat_hunt", "hunt_focus": "data_exfiltration"}
])

# Data summary
summary = client.get_data_summary(hours=24)
```

### JavaScript/Node.js

```javascript
class SecurityAIClient {
    constructor(baseUrl = "http://localhost:8080", apiKey = null) {
        this.baseUrl = baseUrl;
        this.headers = {"Content-Type": "application/json"};
        if (apiKey) {
            this.headers["X-API-Key"] = apiKey;
        }
    }

    async healthCheck() {
        const response = await fetch(`${this.baseUrl}/health`);
        return response.json();
    }

    async analyzeHoneypot(period = "24h", sources = ["cowrie", "dionaea"], focusAreas = null) {
        const data = {
            period: period,
            sources: sources,
            focus_areas: focusAreas
        };
        const response = await fetch(`${this.baseUrl}/analyze/honeypot`, {
            method: "POST",
            headers: this.headers,
            body: JSON.stringify(data)
        });
        return response.json();
    }

    async query(question) {
        const data = {query: question};
        const response = await fetch(`${this.baseUrl}/query`, {
            method: "POST", 
            headers: this.headers,
            body: JSON.stringify(data)
        });
        return response.json();
    }
}

// Usage
const client = new SecurityAIClient("http://localhost:8080", "your-api-key");
const result = await client.analyzeHoneypot("1h");
```

## Integration Examples

### Grafana Dashboard

You can integrate the AI analysis into Grafana dashboards using the JSON API data source:

1. Add a JSON API data source pointing to your AI agent
2. Create panels that query the analysis endpoints
3. Display AI insights alongside your existing metrics

### Automated Alerting

```bash
#!/bin/bash
# Example alert script

RESPONSE=$(curl -s -X POST "http://localhost:8080/analyze/honeypot" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"period": "1h", "sources": ["cowrie"]}')

ANALYSIS=$(echo "$RESPONSE" | jq -r '.analysis.ai_analysis')

if echo "$ANALYSIS" | grep -i "critical\|severe\|attack"; then
    echo "Security alert detected: $ANALYSIS" | mail -s "Security Alert" admin@example.com
fi
```

## Configuration

The API behavior can be configured through environment variables:

- `OLLAMA_HOST`: Ollama server host (default: 192.168.1.132)
- `OLLAMA_PORT`: Ollama server port (default: 11434)
- `API_HOST`: API server host (default: 0.0.0.0)
- `API_PORT`: API server port (default: 8080)
- `API_KEY`: API key for authentication (optional)
- `GRAFANA_HOST`: Grafana server host (default: 192.168.1.135)
- `LOKI_HOST`: Loki server host (default: 192.168.1.135)
- `PROMETHEUS_HOST`: Prometheus server host (default: 192.168.1.135)

## Support

For issues and feature requests, please visit the [GitHub repository](https://github.com/garrigueta/network-security-monitor).