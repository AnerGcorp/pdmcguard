# PDMCGuard — Build & Development
# SPDX-License-Identifier: AGPL-3.0-or-later

BINARY   := pdmcguard
MODULE   := github.com/AnerGcorp/pdmcguard
CMD      := ./cmd/pdmcguard

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS  := -s -w \
  -X main.version=$(VERSION) \
  -X main.commit=$(COMMIT) \
  -X main.date=$(DATE)

# ── Build ────────────────────────────────────────────────────────────────────

.PHONY: build
build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

.PHONY: build-all
build-all: ## Cross-compile for all supported targets
	GOOS=darwin  GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-amd64   $(CMD)
	GOOS=darwin  GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-darwin-arm64   $(CMD)
	GOOS=linux   GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-amd64    $(CMD)
	GOOS=linux   GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-arm64    $(CMD)

# ── Test ─────────────────────────────────────────────────────────────────────

.PHONY: test
test:
	go test ./... -v -race -count=1

.PHONY: test-cover
test-cover:
	go test ./... -race -coverprofile=coverage.txt -covermode=atomic
	go tool cover -func=coverage.txt

# ── Lint ─────────────────────────────────────────────────────────────────────

.PHONY: lint
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run ./...

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: vet
vet:
	go vet ./...

# ── Dev ──────────────────────────────────────────────────────────────────────

.PHONY: run
run: build
	./$(BINARY) $(ARGS)

.PHONY: clean
clean:
	rm -f $(BINARY)
	rm -rf dist/

.PHONY: help
help:
	@echo "PDMCGuard Development"
	@echo ""
	@echo "  make build       Build for current platform"
	@echo "  make build-all   Cross-compile for darwin/linux (amd64+arm64)"
	@echo "  make test        Run tests with race detector"
	@echo "  make test-cover  Run tests with coverage report"
	@echo "  make lint        Run golangci-lint"
	@echo "  make fmt         Format Go source files"
	@echo "  make vet         Run go vet"
	@echo "  make clean       Remove build artifacts"
