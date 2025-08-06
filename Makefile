# Makefile for Lux Threshold Signatures Library
# Supports CGG21, FROST, and LSS-MPC protocols

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOLINT=golangci-lint
GOCOVER=$(GOCMD) tool cover

# Binary names
BINARY_NAME=threshold
BINARY_UNIX=$(BINARY_NAME)_unix
BINARY_WINDOWS=$(BINARY_NAME).exe

# Build flags
LDFLAGS=-ldflags "-s -w"
BUILDFLAGS=-v

# Test flags
TESTFLAGS=-v -race -coverprofile=coverage.out -covermode=atomic
BENCHFLAGS=-bench=. -benchmem -benchtime=10s

# Package lists
PACKAGES=$(shell go list ./... | grep -v /vendor/)
INTEGRATION_PACKAGES=./protocols/...

# Default target
.DEFAULT_GOAL := default

## default: Build and run tests
default: build test

## help: Show this help message
help:
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## all: Build and test everything
all: clean deps lint test build

## build: Build all packages
build:
	$(GOBUILD) $(BUILDFLAGS) ./...

## build-cli: Build the threshold CLI tool
build-cli:
	$(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o bin/threshold-cli ./cmd/threshold-cli

## build-all: Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o $(BINARY_UNIX) ./...
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o $(BINARY_WINDOWS) ./...
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o $(BINARY_NAME)_darwin ./...
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(BUILDFLAGS) $(LDFLAGS) -o $(BINARY_NAME)_darwin_arm64 ./...

## clean: Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f $(BINARY_WINDOWS)
	rm -f $(BINARY_NAME)_darwin*
	rm -f coverage.out coverage.html
	rm -rf dist/

## deps: Download dependencies
deps:
	$(GOGET) -v ./...
	$(GOMOD) download
	$(GOMOD) tidy

## test: Run all tests
test:
	$(GOTEST) $(TESTFLAGS) $(PACKAGES)

## test-short: Run short tests
test-short:
	$(GOTEST) -short $(PACKAGES)

## test-unit: Run unit tests only
test-unit:
	$(GOTEST) $(TESTFLAGS) $(shell go list ./... | grep -v /protocols/)

## test-integration: Run integration tests
test-integration:
	$(GOTEST) $(TESTFLAGS) $(INTEGRATION_PACKAGES)

## test-lss: Run LSS protocol tests
test-lss:
	$(GOTEST) $(TESTFLAGS) ./protocols/lss/...

## test-cmp: Run CMP (CGG21) protocol tests
test-cmp:
	$(GOTEST) $(TESTFLAGS) ./protocols/cmp/...

## test-frost: Run FROST protocol tests
test-frost:
	$(GOTEST) $(TESTFLAGS) ./protocols/frost/...

## test-coverage: Generate test coverage report
test-coverage: test
	$(GOCOVER) -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## test-coverage-view: View coverage in browser
test-coverage-view: test-coverage
	open coverage.html || xdg-open coverage.html

## bench: Run benchmarks
bench:
	$(GOTEST) $(BENCHFLAGS) $(PACKAGES)

## bench-lss: Run LSS protocol benchmarks
bench-lss:
	$(GOTEST) $(BENCHFLAGS) ./protocols/lss/...

## bench-compare: Compare benchmark results
bench-compare:
	@echo "Running baseline benchmarks..."
	$(GOTEST) $(BENCHFLAGS) $(PACKAGES) > bench-base.txt
	@echo "Make your changes, then press Enter to run comparison benchmarks..."
	@read _
	$(GOTEST) $(BENCHFLAGS) $(PACKAGES) > bench-new.txt
	benchstat bench-base.txt bench-new.txt

## lint: Run linters
lint:
	$(GOLINT) run ./...

## lint-fix: Fix linting issues
lint-fix:
	$(GOLINT) run --fix ./...

## fmt: Format code
fmt:
	go fmt ./...
	goimports -w .

## vet: Run go vet
vet:
	go vet ./...

## sec: Run security checks
sec:
	gosec -quiet ./...

## mod-verify: Verify dependencies
mod-verify:
	$(GOMOD) verify

## mod-update: Update dependencies
mod-update:
	$(GOGET) -u ./...
	$(GOMOD) tidy

## install-tools: Install required tools
install-tools:
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) github.com/securego/gosec/v2/cmd/gosec@latest
	$(GOGET) golang.org/x/tools/cmd/goimports@latest
	$(GOGET) golang.org/x/perf/cmd/benchstat@latest

## docker-build: Build Docker image
docker-build:
	docker build -t threshold:latest .

## docker-test: Run tests in Docker
docker-test:
	docker run --rm threshold:latest make test

## ci: Run CI pipeline locally
ci: clean deps lint test build

## release: Create a new release
release: clean test
	@echo "Creating release..."
	goreleaser release --clean

## release-snapshot: Create a snapshot release
release-snapshot:
	goreleaser release --snapshot --clean

## proto: Generate protobuf files
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/*.proto

## docs: Generate documentation
docs:
	godoc -http=:6060

## examples: Build examples
examples:
	$(GOBUILD) -o bin/example ./example/example.go
	$(GOBUILD) -o bin/dynamic_reshare_example ./example/dynamic_reshare_example.go

## run-example: Run the basic example
run-example: examples
	./bin/example

## run-dynamic-reshare: Run dynamic reshare example
run-dynamic-reshare: examples
	./bin/dynamic_reshare_example

.PHONY: all build build-cli build-all clean deps test test-short test-unit test-integration \
	test-lss test-cmp test-frost test-coverage test-coverage-view bench bench-lss \
	bench-compare lint lint-fix fmt vet sec mod-verify mod-update install-tools \
	docker-build docker-test ci release release-snapshot proto docs examples \
	run-example run-dynamic-reshare help