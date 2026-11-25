# Padix Core

Padix Host Vulnerability Scanner (v0.1.39)

## Overview

Padix is a Go-based host vulnerability scanner that performs service discovery, fingerprinting, OS detection, general vulnerability assessment, and CVE correlation on target hosts.

## Features

- Service discovery (HTTP, HTTPS, SMTP, FTP, SSH, Redis, MySQL, PostgreSQL, MSSQL, Oracle, POP3, IMAP, DNS, SMB, RDP, VNC)
- OS detection from service banners and open ports
- General vulnerability assessment (SQL injection, XSS, directory listing, WordPress)
- CVE correlation via local CVE database
- Text and JSON report output (JSON requires an output file path)
- Interactive target input when no target is provided

## Getting Started

### Prerequisites

- Go 1.21+

### Installation

```bash
# Build from source
cd core
make build

# Or install via go install
make install
```

This builds the `padix` binary into `core/bin/padix`.

### Usage

```bash
# Scan a target (interactive prompt if no target given)
padix scan --target example.com

# Scan with JSON output to a file
padix scan --target 192.168.1.1 --format json --output report.json

# Scan using text output (default)
padix scan --target example.com --format text

# Update CVE database
padix db update

# Show CVE database information
padix db status

# Show version
padix version

# Show help
padix help
```

### Scan Options

| Option     | Description                                 |
| ---------- | ------------------------------------------- |
| `--target` | Target IP address or domain                 |
| `--format` | Report format: `text` (default) or `json`   |
| `--output` | Report output file path (required for JSON) |

### Database Commands

```bash
# Update the CVE database (incremental import by default)
padix db update

# Re-import all CVE files
padix db update --full

# Import only files changed since the last successful update
padix db update --incremental

# Show database information
padix db status

```

## Development

```bash
# Build
make build

# Install
make install

# Run with arguments
make scan ARGS="--target=192.2.2.2"

# Run database command
make db ARGS="update"

# Run tests
make test

# Run vet
make vet

# Format code
make fmt

# Lint
make lint

# Download dependencies
make deps

# Tidy modules
make tidy

# Clean build artifacts
make clean
```

## License

See LICENSE for details.

## TODO

- [ ] Search CVE: `padix db search --query "OpenSSH"`
- [ ] Search by CVE ID: `padix db search --id CVE-2024-6387`
- [ ] Run correlation against local database: `padix db test --product OpenSSH --version 9.2p1`
