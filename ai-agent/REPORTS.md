# AI Security Reports Integration with Grafana

## Overview

This system provides AI-powered periodic security reports with multiple complexity levels and seamless Grafana integration. The reports are automatically generated on configurable schedules and can be viewed directly in Grafana dashboards.

## Report Levels

### 1. Executive Summary (`executive`)
- **Audience**: Management, executives, non-technical stakeholders
- **Frequency**: Daily (8 AM)
- **Content**:
  - Overall security score (0-100)
  - Current threat level (LOW/MEDIUM/HIGH/CRITICAL)
  - Top 3-5 key findings
  - Strategic recommendations
  - Business impact analysis
  - Trend analysis
- **Format**: Clean HTML with charts, JSON for API

### 2. Technical Analysis (`technical`)
- **Audience**: Security teams, system administrators
- **Frequency**: Daily (8 AM)
- **Content**:
  - Detailed attack vector breakdown
  - Vulnerability assessment
  - Incident timeline
  - Network security analysis
  - Honeypot activity analysis
  - Technical mitigation steps
- **Format**: Detailed HTML with technical data, JSON

### 3. Detailed Forensics (`detailed`)
- **Audience**: Security analysts, forensic investigators
- **Frequency**: Weekly (Monday 8 AM)
- **Content**:
  - Raw security events
  - Event correlation analysis
  - Threat intelligence integration
  - Evidence chain analysis
  - Attack attribution analysis
  - Indicators of Compromise (IOC) analysis
- **Format**: Comprehensive reports with all raw data

### 4. Real-time Alerts (`real_time`)
- **Audience**: Security operations center (SOC)
- **Frequency**: Event-driven (immediate)
- **Content**:
  - Critical security alerts
  - Immediate response actions
  - Context and severity information
  - Automated escalation
- **Format**: JSON for integration with alerting systems

## API Endpoints

### Report Generation
```bash
# Generate ad-hoc report
POST /reports/generate
{
  "level": "executive",
  "period_hours": 24,
  "focus_areas": ["brute_force", "malware"],
  "export_format": "html"
}

# Response
{
  "success": true,
  "report_id": "550e8400-e29b-41d4-a716-446655440000",
  "level": "executive",
  "status": "completed",
  "download_url": "/reports/550e8400-e29b-41d4-a716-446655440000/export?format=html"
}
```

### Report Management
```bash
# List reports
GET /reports?level=executive&page=1&page_size=50

# Get specific report
GET /reports/{report_id}

# Export report
GET /reports/{report_id}/export?format=html
```

### Scheduler Management
```bash
# Get scheduler status
GET /reports/schedule/status

# Trigger manual report
POST /reports/schedule/trigger?level=executive&period_hours=24
```

## Grafana Integration

### Dashboard Setup

1. **Import Dashboard**:
   ```bash
   # Copy the dashboard JSON to Grafana
   cp monitoring/grafana/dashboards/ai-security-reports.json /path/to/grafana/dashboards/
   ```

2. **Configure Data Source**:
   - Add JSON API data source pointing to your AI agent
   - URL: `http://ai-agent:8080`
   - Add API key authentication header

3. **Set Variables**:
   - `api_key`: Your AI agent API key
   - Configure refresh intervals (default: 5 minutes)

### Dashboard Panels

1. **Security Score Trend**: Real-time security score visualization
2. **Current Threat Level**: Color-coded threat level indicator
3. **Recent Reports**: Table of latest generated reports
4. **Executive Summary**: Latest executive report content
5. **Key Security Metrics**: Important security metrics
6. **Report Generation Schedule**: Upcoming scheduled reports
7. **AI Analysis Insights**: Latest AI-generated insights

### Alerting Configuration

Create Grafana alerts based on report data:

```json
{
  "alert": {
    "name": "Critical Security Score",
    "conditions": [
      {
        "query": {
          "queryType": "",
          "refId": "A",
          "model": {
            "url": "http://ai-agent:8080/reports",
            "method": "GET"
          }
        },
        "reducer": {
          "type": "last",
          "params": []
        },
        "evaluator": {
          "params": [30],
          "type": "lt"
        }
      }
    ],
    "executionErrorState": "alerting",
    "frequency": "5m",
    "handler": 1,
    "name": "Critical Security Score",
    "noDataState": "no_data",
    "notifications": []
  }
}
```

## Configuration

### Environment Variables

```bash
# Report generation
REPORTS_ENABLED=true
REPORTS_RETENTION_DAYS=90
REPORTS_EXPORT_FORMATS=json,html,pdf

# Scheduler configuration
EXECUTIVE_REPORTS_FREQUENCY=daily
TECHNICAL_REPORTS_FREQUENCY=daily
DETAILED_REPORTS_FREQUENCY=weekly
REALTIME_ALERTS_ENABLED=true

# Grafana integration
GRAFANA_INTEGRATION_ENABLED=true
GRAFANA_WEBHOOK_URL=http://grafana:3000/api/annotations
```

### Report Configuration

```python
# ai_agent/config.py
class Settings(BaseSettings):
    # ... existing settings ...
    
    # Report settings
    reports_enabled: bool = True
    reports_retention_days: int = 90
    executive_frequency: str = "daily"
    technical_frequency: str = "daily"
    detailed_frequency: str = "weekly"
    
    # Grafana integration
    grafana_integration: bool = True
    grafana_webhook_url: str = "http://grafana:3000/api/annotations"
```

## Deployment

### Docker Compose Update

Add to your `ai-agent/docker-compose.yml`:

```yaml
services:
  ai-agent:
    # ... existing configuration ...
    volumes:
      - ./reports:/app/reports  # Persist reports
    environment:
      - REPORTS_ENABLED=true
      - GRAFANA_INTEGRATION_ENABLED=true
```

### Build and Deploy

```bash
# Rebuild with new dependencies
cd ai-agent
docker compose up -d --build

# Verify reports directory is created
docker exec -it network-security-ai-agent ls -la /app/reports
```

## Usage Examples

### 1. Generate Executive Report for Board Meeting

```bash
curl -X POST "http://localhost:8080/reports/generate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "level": "executive",
    "period_hours": 168,
    "focus_areas": ["general"],
    "export_format": "html"
  }'
```

### 2. Security Incident Analysis

```bash
curl -X POST "http://localhost:8080/reports/generate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "level": "detailed",
    "period_hours": 24,
    "focus_areas": ["incident_response"],
    "export_format": "json"
  }'
```

### 3. Daily Operations Dashboard

Access the Grafana dashboard at: `http://your-grafana:3000/d/ai-security-reports`

### 4. Automated Report Distribution

```bash
#!/bin/bash
# Daily executive report email script

REPORT_ID=$(curl -s -X POST "http://localhost:8080/reports/schedule/trigger?level=executive" \
  -H "X-API-Key: $API_KEY" | jq -r '.report_id')

# Wait for generation
sleep 30

# Get HTML report
curl -s "http://localhost:8080/reports/$REPORT_ID/export?format=html" \
  -H "X-API-Key: $API_KEY" > daily_security_report.html

# Email the report
mail -s "Daily Security Report" -a "Content-Type: text/html" \
  executives@company.com < daily_security_report.html
```

## Monitoring and Maintenance

### Health Checks

```bash
# Check scheduler status
curl "http://localhost:8080/reports/schedule/status" \
  -H "X-API-Key: your-api-key"

# Check recent reports
curl "http://localhost:8080/reports?page_size=5" \
  -H "X-API-Key: your-api-key"
```

### Log Monitoring

```bash
# Monitor report generation logs
docker logs -f network-security-ai-agent | grep -i "report"

# Check for errors
docker logs network-security-ai-agent | grep -i "error.*report"
```

### Cleanup and Maintenance

The system automatically:
- Cleans up reports older than configured retention period (default: 90 days)
- Rotates log files
- Manages storage space

Manual cleanup:
```bash
# Clean reports older than 30 days
find ./reports -name "*.json" -mtime +30 -delete
```

## Troubleshooting

### Common Issues

1. **Reports not generating**:
   - Check scheduler status: `GET /reports/schedule/status`
   - Verify AI engine connectivity
   - Check data source availability

2. **Grafana dashboard not updating**:
   - Verify API key configuration
   - Check network connectivity to AI agent
   - Review Grafana data source settings

3. **Missing reports**:
   - Check retention policy settings
   - Verify storage permissions
   - Review cleanup job logs

### Performance Optimization

1. **Report Generation**:
   - Adjust analysis periods for large datasets
   - Configure appropriate focus areas
   - Monitor AI engine response times

2. **Storage Management**:
   - Implement report compression
   - Configure appropriate retention periods
   - Monitor disk space usage

3. **Grafana Performance**:
   - Optimize refresh intervals
   - Cache frequently accessed reports
   - Use appropriate data source timeouts