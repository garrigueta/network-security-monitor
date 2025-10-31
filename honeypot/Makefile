.PHONY: help up down restart logs clean status backup

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: ## Start all honeypot services
	docker-compose up -d

down: ## Stop all honeypot services
	docker-compose down

restart: ## Restart all honeypot services
	docker-compose restart

logs: ## View logs from all services
	docker-compose logs -f

logs-cowrie: ## View Cowrie SSH/Telnet logs
	docker-compose logs -f cowrie

logs-dionaea: ## View Dionaea malware logs
	docker-compose logs -f dionaea

logs-promtail: ## View Promtail logs
	docker-compose logs -f promtail

ps: ## Show running services
	docker-compose ps

status: ## Check honeypot status and stats
	@echo "=== Docker Compose Services ==="
	@docker-compose ps
	@echo ""
	@echo "=== Recent Cowrie Attacks ==="
	@docker-compose exec -T cowrie tail -5 /cowrie/cowrie-git/var/log/cowrie/cowrie.log 2>/dev/null || echo "Cowrie not running or no logs yet"

attacks: ## Show recent attack statistics
	@echo "=== Cowrie Login Attempts (Last 100) ==="
	@docker-compose exec -T cowrie grep "login attempt" /cowrie/cowrie-git/var/log/cowrie/cowrie.log 2>/dev/null | tail -20 || echo "No attacks logged yet"

malware: ## List captured malware samples
	@echo "=== Cowrie Downloads ==="
	@docker-compose exec -T cowrie ls -lh /cowrie/cowrie-git/var/lib/cowrie/downloads/ 2>/dev/null || echo "No malware captured yet"
	@echo ""
	@echo "=== Dionaea Binaries ==="
	@docker-compose exec -T dionaea ls -lh /opt/dionaea/var/lib/dionaea/binaries/ 2>/dev/null || echo "No binaries captured yet"

backup: ## Backup logs and malware samples
	@mkdir -p backups/$$(date +%Y%m%d)
	@echo "Backing up to backups/$$(date +%Y%m%d)/"
	@docker cp cowrie:/cowrie/cowrie-git/var/log/ backups/$$(date +%Y%m%d)/cowrie-logs/ 2>/dev/null || echo "Cowrie logs backup failed"
	@docker cp cowrie:/cowrie/cowrie-git/var/lib/cowrie/downloads/ backups/$$(date +%Y%m%d)/malware-samples/ 2>/dev/null || echo "Cowrie downloads backup failed"
	@docker cp dionaea:/opt/dionaea/var/lib/dionaea/binaries/ backups/$$(date +%Y%m%d)/dionaea-binaries/ 2>/dev/null || echo "Dionaea binaries backup failed"
	@echo "Backup complete!"

clean: ## Stop and remove all containers and volumes
	docker-compose down -v

rebuild: ## Rebuild and restart all services
	docker-compose up -d --build

update: ## Pull latest images and restart
	docker-compose pull
	docker-compose up -d

test-loki: ## Test connectivity to Loki
	@echo "Testing connection to Loki..."
	@curl -s $$LOKI_URL/ready && echo "Loki is reachable!" || echo "Cannot reach Loki at $$LOKI_URL"
