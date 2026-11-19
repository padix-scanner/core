
# Padix - Host Vulnerability Scanner

APP_NAME := padix
MODULE := ./cmd/core
BUILD_DIR := bin
BINARY := $(BUILD_DIR)/$(APP_NAME)

GO := go

.PHONY: all build run scan test lint fmt vet clean deps tidy install help

all: fmt test build

## Build

build:
	@mkdir -p $(BUILD_DIR)
	@echo "Building $(APP_NAME)..."
	$(GO) build -trimpath -ldflags="-s -w" -o $(BINARY) $(MODULE)

install:
	$(GO) install $(MODULE)

## Run

run: build
	./$(BINARY)

scan: build
	./$(BINARY)

## Test

test:
	$(GO) test -race -cover ./...

## Code Quality

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

## Dependencies

deps:
	$(GO) mod download

tidy:
	$(GO) mod tidy

## Cleanup

clean:
	rm -rf $(BUILD_DIR)
	$(GO) clean

## Help

help:
	@echo "Dazhvar - Makefile Commands"
	@echo ""
	@echo "  make build    Build binary"
	@echo "  make run      Build and run scanner"
	@echo "  make scan     Run host scan"
	@echo "  make test     Run tests with race detection"
	@echo "  make lint     Run golangci-lint"
	@echo "  make fmt      Format Go source"
	@echo "  make vet      Run Go vet"
	@echo "  make deps     Download dependencies"
	@echo "  make tidy     Tidy Go modules"
	@echo "  make install  Install binary"
	@echo "  make clean    Remove build artifacts"
	@echo "  make all      Format, test and build"
