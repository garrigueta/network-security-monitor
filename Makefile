.PHONY: help build deploy install upgrade uninstall clean status logs dashboard images permissions all

# Variables
NAMESPACE := network-security
RELEASE_NAME := nsm
CHART_PATH := ./helm-chart/network-security-monitor
DASHBOARD_PATH := $(CHART_PATH)/dashboards
IMAGES := zeek crypto-exporter ai-agent test-simulator

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)Network Security Monitor - Makefile$(NC)"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'

build: ## Build all Docker images
	@echo "$(GREEN)Building Docker images...$(NC)"
	@cd monitoring/zeek && docker build -t network-security/zeek:latest .
	@cd monitoring/crypto-exporter && docker build -t network-security/crypto-exporter:latest .
	@cd ai-agent && docker build -t network-security/ai-agent:latest .
	@cd test-simulator && docker build -t network-security/test-simulator:latest .
	@echo "$(GREEN)All images built successfully$(NC)"

images: ## Import Docker images into k3s
	@echo "$(GREEN)Importing images into k3s...$(NC)"
	@for img in $(IMAGES); do \
		echo "Importing network-security/$$img:latest..."; \
		docker save network-security/$$img:latest | sudo k3s ctr images import -; \
	done
	@echo "$(GREEN)All images imported successfully$(NC)"

permissions: ## Fix permissions for Grafana dashboard directory
	@echo "$(GREEN)Setting permissions for Grafana dashboards...$(NC)"
	@sudo chown -R 472:472 $(DASHBOARD_PATH)
	@sudo chmod -R 775 $(DASHBOARD_PATH)
	@echo "$(GREEN)Permissions set successfully$(NC)"

install: permissions ## Install the Helm chart (first time deployment)
	@echo "$(GREEN)Installing Helm chart...$(NC)"
	@helm install $(RELEASE_NAME) $(CHART_PATH) --namespace $(NAMESPACE) --create-namespace
	@echo "$(GREEN)Deployment complete!$(NC)"
	@make status

deploy: upgrade ## Alias for upgrade

upgrade: permissions ## Upgrade existing Helm deployment
	@echo "$(GREEN)Upgrading Helm chart...$(NC)"
	@helm upgrade $(RELEASE_NAME) $(CHART_PATH) --namespace $(NAMESPACE)
	@echo "$(GREEN)Upgrade complete!$(NC)"
	@make status

uninstall: ## Uninstall the Helm release
	@echo "$(YELLOW)Uninstalling Helm release...$(NC)"
	@helm uninstall $(RELEASE_NAME) -n $(NAMESPACE)
	@echo "$(GREEN)Uninstalled successfully$(NC)"

clean: uninstall ## Uninstall and delete all PVCs and PVs
	@echo "$(YELLOW)Cleaning up resources...$(NC)"
	@kubectl delete pvc -n $(NAMESPACE) --all
	@kubectl delete pv --all
	@echo "$(GREEN)Cleanup complete$(NC)"

status: ## Show deployment status
	@echo "$(GREEN)=== Helm Release Status ===$(NC)"
	@helm status $(RELEASE_NAME) -n $(NAMESPACE) 2>/dev/null || echo "Release not found"
	@echo ""
	@echo "$(GREEN)=== Pods Status ===$(NC)"
	@kubectl get pods -n $(NAMESPACE)
	@echo ""
	@echo "$(GREEN)=== Services ===$(NC)"
	@kubectl get svc -n $(NAMESPACE)

logs: ## Show logs for all pods (use POD=<name> for specific pod)
ifdef POD
	@kubectl logs -n $(NAMESPACE) $(POD) --tail=100 -f
else
	@echo "$(YELLOW)Showing recent logs from all pods...$(NC)"
	@kubectl logs -n $(NAMESPACE) --all-containers=true --tail=20
endif

dashboard: ## Open Grafana dashboard in browser
	@echo "$(GREEN)Grafana URL: http://192.168.1.136:3000$(NC)"
	@echo "Username: admin"
	@echo "Password: admin"

restart-promtail: ## Restart Promtail pod to reload configuration
	@echo "$(GREEN)Restarting Promtail...$(NC)"
	@kubectl delete pod -n $(NAMESPACE) -l app.kubernetes.io/component=promtail
	@echo "$(GREEN)Promtail restarted$(NC)"

restart-grafana: ## Restart Grafana pod
	@echo "$(GREEN)Restarting Grafana...$(NC)"
	@kubectl delete pod -n $(NAMESPACE) -l app.kubernetes.io/component=grafana
	@echo "$(GREEN)Grafana restarted$(NC)"

all: build images install ## Build, import images, and install everything

.DEFAULT_GOAL := help
