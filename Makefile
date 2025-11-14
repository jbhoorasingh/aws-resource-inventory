.PHONY: help build up down logs shell test clean migrate collectstatic superuser backup restore

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)AWS Resource Inventory - Docker Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

# Production commands
build: ## Build production containers
	@echo "$(BLUE)Building production containers...$(NC)"
	docker-compose build --no-cache

up: ## Start production services
	@echo "$(BLUE)Starting production services...$(NC)"
	docker-compose --env-file .env.production up -d
	@echo "$(GREEN)Services started! Access at http://localhost$(NC)"

down: ## Stop production services
	@echo "$(BLUE)Stopping production services...$(NC)"
	docker-compose down

restart: ## Restart production services
	@echo "$(BLUE)Restarting production services...$(NC)"
	docker-compose restart

logs: ## View production logs (follow)
	docker-compose logs -f

logs-web: ## View web service logs
	docker-compose logs -f web

logs-db: ## View database logs
	docker-compose logs -f db

logs-nginx: ## View nginx logs
	docker-compose logs -f nginx

# Development commands
dev-up: ## Start development services
	@echo "$(BLUE)Starting development services...$(NC)"
	docker-compose -f docker-compose.dev.yml up -d
	@echo "$(GREEN)Development server started at http://localhost:8000$(NC)"

dev-down: ## Stop development services
	docker-compose -f docker-compose.dev.yml down

dev-logs: ## View development logs
	docker-compose -f docker-compose.dev.yml logs -f

dev-shell: ## Open shell in development container
	docker-compose -f docker-compose.dev.yml exec web /bin/bash

# Management commands
shell: ## Open Django shell
	docker-compose exec web python manage.py shell

bash: ## Open bash shell in web container
	docker-compose exec web /bin/bash

migrate: ## Run database migrations
	@echo "$(BLUE)Running migrations...$(NC)"
	docker-compose exec web python manage.py migrate

makemigrations: ## Create new migrations
	@echo "$(BLUE)Creating migrations...$(NC)"
	docker-compose exec web python manage.py makemigrations

collectstatic: ## Collect static files
	@echo "$(BLUE)Collecting static files...$(NC)"
	docker-compose exec web python manage.py collectstatic --noinput

superuser: ## Create Django superuser
	docker-compose exec web python manage.py createsuperuser

dbshell: ## Open database shell
	docker-compose exec db psql -U awsinventory -d awsinventory

# Testing
test: ## Run tests
	@echo "$(BLUE)Running tests...$(NC)"
	docker-compose exec web python manage.py test resources.tests

test-coverage: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	docker-compose exec web pytest --cov=resources --cov-report=html

# Backup and restore
backup: ## Backup database
	@echo "$(BLUE)Creating database backup...$(NC)"
	@mkdir -p backups
	docker-compose exec -T db pg_dump -U awsinventory awsinventory | gzip > backups/db_backup_$$(date +%Y%m%d_%H%M%S).sql.gz
	@echo "$(GREEN)Backup created in backups/$(NC)"

restore: ## Restore database from backup (requires BACKUP_FILE variable)
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "$(RED)Error: BACKUP_FILE not specified$(NC)"; \
		echo "Usage: make restore BACKUP_FILE=backups/db_backup_20250114_120000.sql.gz"; \
		exit 1; \
	fi
	@echo "$(BLUE)Restoring database from $(BACKUP_FILE)...$(NC)"
	gunzip < $(BACKUP_FILE) | docker-compose exec -T db psql -U awsinventory -d awsinventory
	@echo "$(GREEN)Database restored!$(NC)"

# Maintenance
clean: ## Remove all containers, volumes, and images
	@echo "$(RED)WARNING: This will remove all containers, volumes, and images!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose down -v --rmi all; \
		echo "$(GREEN)Cleanup complete!$(NC)"; \
	else \
		echo "Aborted."; \
	fi

prune: ## Remove unused Docker resources
	@echo "$(BLUE)Pruning unused Docker resources...$(NC)"
	docker system prune -af --volumes
	@echo "$(GREEN)Prune complete!$(NC)"

ps: ## Show running containers
	docker-compose ps

stats: ## Show container resource usage
	docker stats

health: ## Check application health
	@echo "$(BLUE)Checking application health...$(NC)"
	@curl -f http://localhost/health/ && echo "$(GREEN)✓ Application is healthy$(NC)" || echo "$(RED)✗ Application is down$(NC)"

# Installation
install-gunicorn: ## Install gunicorn dependency
	poetry add gunicorn

update-deps: ## Update dependencies
	poetry update
	poetry export -f requirements.txt --output requirements.txt --without-hashes

# Quick commands
quick-start: build up migrate collectstatic ## Build, start, migrate, and collect static files
	@echo "$(GREEN)Application ready at http://localhost$(NC)"

quick-dev: dev-up ## Quick start for development
	@echo "$(GREEN)Development server ready at http://localhost:8000$(NC)"
