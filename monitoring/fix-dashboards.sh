#!/bin/bash

# Simple dashboard fix script
# Fixes data source UIDs and mount points after first startup

echo "🔧 Fixing dashboard configurations..."

# Wait for Grafana
echo "⏳ Waiting for Grafana..."
while ! curl -s http://localhost:3000/api/health &>/dev/null; do sleep 2; done

# Get data source UIDs
LOKI_UID=$(curl -s -u admin:admin http://localhost:3000/api/datasources/name/Loki | grep -o '"uid":"[^"]*"' | cut -d'"' -f4)
PROMETHEUS_UID=$(curl -s -u admin:admin http://localhost:3000/api/datasources/name/Prometheus | grep -o '"uid":"[^"]*"' | cut -d'"' -f4)

# Fix Zeek dashboards (use Loki)
for file in grafana/dashboards/zeek-{complete,connection,dns-security,security-overview,ssl-tls}-analysis.json; do
    [ -f "$file" ] && sed -i "s/\"uid\": \"[^\"]*\"/\"uid\": \"$LOKI_UID\"/g" "$file"
done

# Fix SSD dashboards (use Prometheus + correct mount point)  
for file in grafana/dashboards/zeek-ssd-{storage,io}.json; do
    [ -f "$file" ] && sed -i "s/\"uid\": \"[^\"]*\"/\"uid\": \"$PROMETHEUS_UID\"/g; s|/mnt/zeek-logs|/mnt/ssd-logs|g" "$file"
done

# Fix SSD usage query syntax
sed -i 's/avg_over_time((100.*\[10m\])/100 * (1 - node_filesystem_avail_bytes{mountpoint="\/mnt\/ssd-logs",fstype!~"tmpfs|overlay"} \/ node_filesystem_size_bytes{mountpoint="\/mnt\/ssd-logs",fstype!~"tmpfs|overlay"})/g' grafana/dashboards/zeek-ssd-storage.json

# Restart Grafana
docker compose restart grafana
echo "✅ Done! Dashboards should now work correctly."