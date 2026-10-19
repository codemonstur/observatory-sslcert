# Certificate Observatory - build & development tasks
#
# Run `make` (or `make help`) for a list of targets.

PORT     ?= 8080
SAMPLE   ?= 2500
OUTPUT   ?= site/data
BINARY   := bin/scanner
GOFMT    := $(shell command -v gofmt 2>/dev/null)

.DEFAULT_GOAL := help

.PHONY: help build run scan serve serve-alt fmt vet test clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build the scanner into bin/scanner
	cd scanner && go build -o ../$(BINARY) .

scan: build ## Build and run a scan (SAMPLE=2500 OUTPUT=site/data)
	./$(BINARY) -sample $(SAMPLE) -output $(OUTPUT)

run: scan ## Alias for scan

serve: ## Serve the site locally on PORT (default 8080)
	cd site && python3 -m http.server $(PORT)

serve-alt: ## Serve the site on a second port (8765) in parallel
	cd site && python3 -m http.server 8765

fmt: ## Format Go sources
	cd scanner && $(if $(GOFMT),gofmt -w .,go fmt ./...)

vet: ## Run go vet on the scanner
	cd scanner && go vet ./...

test: ## Run Go tests
	cd scanner && go test ./...

clean: ## Remove build artifacts
	rm -rf bin scanner/scanner
