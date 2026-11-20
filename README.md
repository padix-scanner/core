# Padix Core

Host Vulnerability Scanner

## Overview

Padix is a Go-based host vulnerability scanner that performs service discovery, fingerprinting, general vulnerability assessment, and CVE correlation on target hosts.

## Features

- Service and technology discovery (HTTP, HTTPS, SMTP, FTP, SSH)
- General vulnerability assessment (XSS, etc.)
- CVE correlation
- Text and JSON report output
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

### Usage

```bash
# Scan a target (interactive prompt if no target given)
padix scan --target example.com

# Scan with JSON output
padix scan --target 192.168.1.1 --format json --output report.json

# Update CVE database
padix db update

# Generate report
padix report

# Show version
padix version
```

### Scan Options

| Option     | Description                                 |
| ---------- | ------------------------------------------- |
| `--target` | Target IP address or domain                 |
| `--format` | Report format: `text` (default) or `json`   |
| `--output` | Report output file path (required for JSON) |

## Development

```bash
# Build
make build

# Run with arguments
make scan ARGS="--target=192.2.2.2"

# Run tests
make test

# Format code
make fmt

# Lint
make lint

# Clean build artifacts
make clean
```

## License

See LICENSE for details.
