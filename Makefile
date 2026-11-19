
# Padix - Host Vulnerability Scanner

APP_NAME := padix
MODULE := ./cmd/core
BUILD_DIR := bin
BINARY := $(BUILD_DIR)/$(APP_NAME)
ARGS ?=
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

run:
	$(GO) run $(MODULE) $(filter-out run,$(MAKECMDGOALS))

scan:
	$(GO) run $(MODULE) scan $(ARGS)

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
