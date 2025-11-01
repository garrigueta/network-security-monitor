# Docker Compose Makefile for easier management

.PHONY: help up down restart logs clean build backup restore

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Complete setup (start services + fix dashboards)
	@echo "🚀 Starting monitoring stack..."
	docker compose up -d
	@echo "⏳ Waiting for services to initialize..."
	@sleep 30
	@echo "🔧 Fixing dashboard configurations..."
	@./fix-dashboards.sh
	@echo "✅ Setup complete! Access Grafana at http://localhost:3000"

up: ## Start all services
	docker compose up -d

down: ## Stop all services
	docker compose down

restart: ## Restart all services
	docker compose restart

logs: ## View logs from all services
	docker compose logs -f

logs-zeek: ## View Zeek logs
	docker compose logs -f zeek

logs-grafana: ## View Grafana logs
	docker compose logs -f grafana

logs-prometheus: ## View Prometheus logs
	docker compose logs -f prometheus

ps: ## Show running services
	docker compose ps

build: ## Build all containers
	docker compose build

rebuild: ## Rebuild and restart all services
	docker compose up -d --build

clean: ## Stop and remove all containers and volumes
	docker compose down -v

status: ## Check service health
	@echo "=== Docker Compose Services ==="
	@docker compose ps
	@echo ""
	@echo "=== Container Logs (Last 10 lines each) ==="
	@echo "--- Zeek ---"
	@docker compose logs --tail=10 zeek 2>/dev/null || echo "Zeek logs not available"
	@echo "--- Prometheus ---"
	@docker compose logs --tail=10 prometheus 2>/dev/null || echo "Prometheus logs not available"
	@echo "--- Grafana ---"
	@docker compose logs --tail=10 grafana 2>/dev/null || echo "Grafana logs not available"
	@echo "--- Loki ---"
	@docker compose logs --tail=10 loki 2>/dev/null || echo "Loki logs not available"
	@echo ""
	@echo "=== SSD Mount Status ==="
	@df -h /mnt/ssd-logs 2>/dev/null || echo "SSD not mounted at /mnt/ssd-logs"
	@echo ""
	@echo "=== Service Health Check ==="
	@curl -s http://localhost:9090/-/healthy >/dev/null && echo "✓ Prometheus: Healthy" || echo "✗ Prometheus: Not responding"
	@curl -s http://localhost:3000/api/health >/dev/null && echo "✓ Grafana: Healthy" || echo "✗ Grafana: Not responding"
	@curl -s http://localhost:3100/ready >/dev/null && echo "✓ Loki: Healthy" || echo "✗ Loki: Not responding"

backup: ## Backup all volumes
	@mkdir -p backups
	@echo "Backing up Prometheus data..."
	@docker run --rm -v docker_prometheus-data:/data -v $(PWD)/backups:/backup ubuntu tar czf /backup/prometheus-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /data .
	@echo "Backing up Loki data..."
	@docker run --rm -v docker_loki-data:/data -v $(PWD)/backups:/backup ubuntu tar czf /backup/loki-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /data .
	@echo "Backing up Grafana data..."
	@docker run --rm -v docker_grafana-data:/data -v $(PWD)/backups:/backup ubuntu tar czf /backup/grafana-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /data .
	@echo "Backup complete!"

update: ## Pull latest images and restart
	docker compose pull
	docker compose up -d
