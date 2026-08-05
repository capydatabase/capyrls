BINARY_NAME := capyrls
MAIN_PACKAGE := ./cmd/capyrls
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CGO_ENABLED ?= 0

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the capyrls binary
	CGO_ENABLED=$(CGO_ENABLED) go build -o $(BINARY_NAME) $(MAIN_PACKAGE)

.PHONY: fmt
fmt: ## Format source
	go fmt ./...

.PHONY: lint
lint: ## Lint (golangci-lint if available, else go vet)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout=5m; \
	else \
		go vet ./...; \
	fi

.PHONY: test
test: ## Run tests with the race detector
	go test -race ./...

.PHONY: check
check: fmt lint test ## fmt + lint + test

.PHONY: release-snapshot
release-snapshot: ## Local GoReleaser snapshot build
	goreleaser release --snapshot --clean

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BINARY_NAME)
	rm -rf dist
