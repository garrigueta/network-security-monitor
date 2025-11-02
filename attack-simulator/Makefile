.PHONY: build run stop logs clean help

help:
	@echo "Attack Simulator - Docker Commands"
	@echo "=================================="
	@echo "make build    - Build the Docker image"
	@echo "make run      - Run attack simulation"
	@echo "make stop     - Stop the container"
	@echo "make logs     - View container logs"
	@echo "make clean    - Remove container and results"
	@echo "make results  - Show latest results"

build:
	docker compose build

run:
	@echo "🚀 Starting attack simulation..."
	docker compose up
	@echo "✅ Simulation complete. Check results/ directory"

stop:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker compose down -v
	rm -rf results/*
	@echo "✅ Cleaned up"

results:
	@echo "📊 Latest Results:"
	@ls -lht results/ | head -5
	@echo ""
	@if [ -n "$$(ls -t results/*.json 2>/dev/null | head -1)" ]; then \
		echo "Summary from latest run:"; \
		cat $$(ls -t results/*.json | head -1) | jq '.[] | {protocol, success, error}' | head -20; \
	fi
