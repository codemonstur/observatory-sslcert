# Certificate Observatory - build & development tasks
#
# Run `make` (or `make help`) for a list of targets.

PORT     ?= 8080
SAMPLE   ?= 2500
OUTPUT   ?= docs/data
BINARY   := bin/scanner
GOFMT    := $(shell command -v gofmt 2>/dev/null)

.DEFAULT_GOAL := help

.PHONY: help build run scan serve serve-alt fmt vet test clean

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_.-]+:' $(MAKEFILE_LIST) | grep -vE '^[a-zA-Z0-9_.-]+:=' | \
		awk 'BEGIN {FS = ":"} /^\./ {next} {name = $$1; sub(/[[:blank:]]+$$/, "", name); doc = $$0; sub(/^[^#]*## /, "", doc); if (doc == $$0) sub(/^[^:]*:[[:blank:]]*/, "", doc); printf "  \033[36m%-10s\033[0m %s\n", name, doc}'

build: ## Build the scanner into bin/scanner
	cd scanner && go build -o ../$(BINARY) .

scan: build ## Build and run a scan (SAMPLE=2500 OUTPUT=docs/data)
	./$(BINARY) -sample $(SAMPLE) -output $(OUTPUT)

run: scan ## Alias for scan

serve: ## Serve the site locally on PORT (default 8080)
	cd docs && python3 -m http.server $(PORT)

serve-alt: ## Serve the site on a second port (8765) in parallel
	cd docs && python3 -m http.server 8765

fmt: ## Format Go sources
	cd scanner && $(if $(GOFMT),gofmt -w .,go fmt ./...)

vet: ## Run go vet on the scanner
	cd scanner && go vet ./...

test: ## Run Go tests
	cd scanner && go test ./...

clean: ## Remove build artifacts
	rm -rf bin scanner/scanner
