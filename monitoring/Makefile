# Docker Compose Makefile for easier management

.PHONY: help up down restart logs clean build backup restore

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: ## Start all services
	docker-compose up -d

down: ## Stop all services
	docker-compose down

restart: ## Restart all services
	docker-compose restart

logs: ## View logs from all services
	docker-compose logs -f

logs-zeek: ## View Zeek logs
	docker-compose logs -f zeek

logs-grafana: ## View Grafana logs
	docker-compose logs -f grafana

logs-prometheus: ## View Prometheus logs
	docker-compose logs -f prometheus

ps: ## Show running services
	docker-compose ps

build: ## Build all containers
	docker-compose build

rebuild: ## Rebuild and restart all services
	docker-compose up -d --build

clean: ## Stop and remove all containers and volumes
	docker-compose down -v

status: ## Check service health
	@echo "=== Docker Compose Services ==="
	@docker-compose ps
	@echo ""
	@echo "=== Zeek Status ==="
	@docker exec zeek zeekctl status || echo "Zeek not running"
	@echo ""
	@echo "=== Prometheus Targets ==="
	@curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}' || echo "Prometheus not accessible"

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
	docker-compose pull
	docker-compose up -d
