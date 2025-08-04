# MyEncrypt Makefile

# Configuration
IMAGE_NAME ?= myencrypt
TAG ?= latest
PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7
PUSH ?= false

# Colors
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

.PHONY: help build build-multi push dev test clean docker-clean

help: ## Show this help message
	@echo "$(BLUE)MyEncrypt Build Commands$(NC)"
	@echo "========================="
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build Docker image for current platform
	@echo "$(YELLOW)🔨 Building Docker image with BuildKit cache mounts...$(NC)"
	DOCKER_BUILDKIT=1 docker buildx build --load -t $(IMAGE_NAME):$(TAG) .
	@echo "$(GREEN)✅ Build complete!$(NC)"

build-multi: ## Build multi-platform Docker image
	@echo "$(YELLOW)🔨 Building multi-platform Docker image with BuildKit...$(NC)"
	./scripts/docker-build.sh
	@echo "$(GREEN)✅ Multi-platform build complete!$(NC)"

push: ## Build and push multi-platform Docker image
	@echo "$(YELLOW)🚀 Building and pushing Docker image...$(NC)"
	PUSH=true ./scripts/docker-build.sh
	@echo "$(GREEN)✅ Push complete!$(NC)"

dev: ## Start development environment
	@echo "$(YELLOW)🚀 Starting development environment...$(NC)"
	docker-compose -f docker-compose.dev.yml up --build -d
	@echo "$(GREEN)✅ Development environment started!$(NC)"
	@echo "$(BLUE)📋 Services:$(NC)"
	@echo "  - MyEncrypt ACME Server: http://localhost:14000"
	@echo "  - Example HTTPS App: https://localhost:8443"
	@echo "  - Nginx Proxy: http://localhost:8080"

dev-logs: ## Show development environment logs
	docker-compose -f docker-compose.dev.yml logs -f

dev-stop: ## Stop development environment
	@echo "$(YELLOW)🛑 Stopping development environment...$(NC)"
	docker-compose -f docker-compose.dev.yml down
	@echo "$(GREEN)✅ Development environment stopped!$(NC)"

prod: ## Start production environment
	@echo "$(YELLOW)🚀 Starting production environment...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✅ Production environment started!$(NC)"
	@echo "$(BLUE)📋 MyEncrypt ACME Server: http://localhost:14000$(NC)"

prod-stop: ## Stop production environment
	@echo "$(YELLOW)🛑 Stopping production environment...$(NC)"
	docker-compose down
	@echo "$(GREEN)✅ Production environment stopped!$(NC)"

run: ## Run the application locally
	@echo "$(YELLOW)🚀 Starting MyEncrypt server...$(NC)"
	go run cmd/myencrypt/main.go run

run-docker: ## Run with Docker
	@echo "$(YELLOW)🐳 Starting MyEncrypt with Docker...$(NC)"
	docker run --rm -p 14000:14000 -v myencrypt_data:/data $(IMAGE_NAME):$(TAG)

run-env: ## Run with container mode (environment variables only)
	@echo "$(YELLOW)🐳 Starting MyEncrypt in container mode...$(NC)"
	go run cmd/myencrypt/main.go run --container

test: ## Run tests
	@echo "$(YELLOW)🧪 Running tests...$(NC)"
	go test -v ./tests/... -timeout 5m
	@echo "$(GREEN)✅ Tests complete!$(NC)"

test-docker: ## Run tests in Docker
	@echo "$(YELLOW)🧪 Running tests in Docker...$(NC)"
	docker run --rm -v $(PWD):/app -w /app golang:1.21-alpine sh -c "apk add --no-cache gcc musl-dev sqlite-dev && go test -v ./tests/... -timeout 5m"
	@echo "$(GREEN)✅ Docker tests complete!$(NC)"

demo: ## Start complete demo environment
	@echo "$(YELLOW)🚀 Starting complete demo environment...$(NC)"
	docker-compose -f docker-compose.demo.yml up --build -d
	@echo "$(GREEN)✅ Demo environment started!$(NC)"
	@echo "$(BLUE)📋 Demo Services:$(NC)"
	@echo "  - MyEncrypt ACME Server: http://localhost:14000"
	@echo "  - Autocert App: https://autocert.local:8443"
	@echo "  - Caddy Proxy Apps: https://app1.local, https://app2.local"
	@echo "  - Traefik Proxy Apps: https://app1-traefik.local:8444, https://app2-traefik.local:8444"
	@echo "  - Traefik Dashboard: https://traefik.local:8444"
	@echo ""
	@echo "$(YELLOW)⚠️  Add these to /etc/hosts:$(NC)"
	@echo "127.0.0.1 autocert.local app1.local app2.local api.local app1-traefik.local app2-traefik.local traefik.local"

demo-logs: ## Show demo environment logs
	docker-compose -f docker-compose.demo.yml logs -f

demo-stop: ## Stop demo environment
	@echo "$(YELLOW)🛑 Stopping demo environment...$(NC)"
	docker-compose -f docker-compose.demo.yml down
	@echo "$(GREEN)✅ Demo environment stopped!$(NC)"

demo-clean: ## Clean demo environment (remove volumes)
	@echo "$(YELLOW)🧹 Cleaning demo environment...$(NC)"
	docker-compose -f docker-compose.demo.yml down -v --remove-orphans
	@echo "$(GREEN)✅ Demo environment cleaned!$(NC)"

demo-status: ## Show demo environment status
	@echo "$(BLUE)📊 Demo Environment Status:$(NC)"
	docker-compose -f docker-compose.demo.yml ps

release: ## Create a new release (requires VERSION)
	@if [ -z "$(VERSION)" ]; then echo "$(RED)❌ VERSION is required. Usage: make release VERSION=v1.0.0$(NC)"; exit 1; fi
	@echo "$(YELLOW)🏷️  Creating release $(VERSION)...$(NC)"
	git tag $(VERSION)
	git push origin $(VERSION)
	@echo "$(GREEN)✅ Release $(VERSION) created! Check GitHub Actions for build progress.$(NC)"

release-dry-run: ## Test release process without creating tag
	@if [ -z "$(VERSION)" ]; then echo "$(RED)❌ VERSION is required. Usage: make release-dry-run VERSION=v1.0.0$(NC)"; exit 1; fi
	@echo "$(YELLOW)🧪 Testing release process for $(VERSION)...$(NC)"
	@echo "Would create tag: $(VERSION)"
	@echo "Would push to: origin $(VERSION)"
	@echo "$(GREEN)✅ Dry run complete!$(NC)"

build-all: ## Build binaries for all platforms
	@echo "$(YELLOW)🔨 Building binaries for all platforms...$(NC)"
	@mkdir -p dist
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "darwin" ] && [ "$$arch" = "amd64" ]; then continue; fi; \
			if [ "$$os" = "windows" ]; then ext=".exe"; else ext=""; fi; \
			echo "Building $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build \
				-ldflags="-w -s -X main.version=dev -X main.commit=$$(git rev-parse --short HEAD) -X main.date=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
				-o dist/myencrypt-$$os-$$arch$$ext cmd/myencrypt/main.go; \
		done; \
	done
	@echo "$(GREEN)✅ All binaries built in dist/ directory!$(NC)"

version: ## Show version information
	@go run -ldflags="-X main.version=dev -X main.commit=$$(git rev-parse --short HEAD) -X main.date=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" cmd/myencrypt/main.go version

lint: ## Run linter
	@echo "$(YELLOW)🔍 Running linter...$(NC)"
	golangci-lint run
	@echo "$(GREEN)✅ Linting complete!$(NC)"

security: ## Run security checks
	@echo "$(YELLOW)🔒 Running security checks...$(NC)"
	gosec ./...
	@echo "$(GREEN)✅ Security check complete!$(NC)"

vuln-check: ## Check for vulnerabilities
	@echo "$(YELLOW)🛡️  Checking for vulnerabilities...$(NC)"
	govulncheck ./...
	@echo "$(GREEN)✅ Vulnerability check complete!$(NC)"

clean: ## Clean up build artifacts
	@echo "$(YELLOW)🧹 Cleaning up...$(NC)"
	go clean
	rm -f myencrypt
	rm -rf dist/
	@echo "$(GREEN)✅ Clean complete!$(NC)"

docker-clean: ## Clean up Docker resources
	@echo "$(YELLOW)🧹 Cleaning up Docker resources...$(NC)"
	docker-compose -f docker-compose.dev.yml down -v --remove-orphans || true
	docker-compose down -v --remove-orphans || true
	docker system prune -f
	@echo "$(GREEN)✅ Docker clean complete!$(NC)"

env-help: ## Show environment variables help
	@echo "$(BLUE)MyEncrypt Environment Variables:$(NC)"
	@echo "================================"
	@echo "$(GREEN)MYENCRYPT_HTTP_PORT$(NC)          HTTP server port (default: 14000)"
	@echo "$(GREEN)MYENCRYPT_BIND_ADDRESS$(NC)       Bind address (default: 0.0.0.0)"
	@echo "$(GREEN)MYENCRYPT_CERT_TTL$(NC)           Individual certificate TTL (default: 24h)"
	@echo "$(GREEN)MYENCRYPT_CA_TTL$(NC)             CA certificate TTL (default: 19200h)"
	@echo "$(GREEN)MYENCRYPT_ALLOWED_DOMAINS$(NC)    Allowed domains, comma-separated"
	@echo "$(GREEN)MYENCRYPT_CERT_STORE_PATH$(NC)    Certificate storage path (default: /data)"
	@echo "$(GREEN)MYENCRYPT_DATABASE_PATH$(NC)      SQLite database file path (default: /data/myencrypt.db)"
	@echo ""
	@echo "$(BLUE)Example:$(NC)"
	@echo "docker run -p 14000:14000 -v myencrypt_data:/data \\"
	@echo "  -e MYENCRYPT_ALLOWED_DOMAINS='localhost,*.localhost,myapp.local,*.myapp.local' \\"
	@echo "  -e MYENCRYPT_DATABASE_PATH='/data/myencrypt.db' \\"
	@echo "  $(IMAGE_NAME):$(TAG)"

# Build info
info: ## Show build information
	@echo "$(BLUE)Build Configuration:$(NC)"
	@echo "===================="
	@echo "$(GREEN)Image Name:$(NC) $(IMAGE_NAME)"
	@echo "$(GREEN)Tag:$(NC) $(TAG)"
	@echo "$(GREEN)Platforms:$(NC) $(PLATFORMS)"
	@echo "$(GREEN)Push:$(NC) $(PUSH)"
