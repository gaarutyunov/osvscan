# Quick Start Guide

This guide will help you get started with the osvscan analyzer in under 5 minutes.

## Prerequisites

- Go 1.24 or later
- Network access (for online mode) or OSV database (for offline mode)

## Installation

### Option 1: Standalone Tool

```bash
cd /home/garutyunov/go-scanner/osvscan
go install ./cmd/osvscan
```

### Option 2: As a Library

```bash
go get github.com/garutyunov/osvscan
```

## Quick Usage

### 1. Scan Your Project

```bash
# Navigate to your Go project
cd /path/to/your/project

# Run the scanner
osvscan ./...
```

### 2. Example Output

```
/path/to/your/project/go.mod:1:1: [HIGH] CVE-2021-3121 in github.com/gogo/protobuf@1.3.1: Improper Input Validation
/path/to/your/project/go.mod:1:1: [MEDIUM] GHSA-xxxx-yyyy-zzzz in golang.org/x/crypto@0.0.0-20200622213623-75b288015ac9: Use of insufficiently random values
```

### 3. Using with golangci-lint

Add to `.golangci.yml`:

```yaml
linters-settings:
  custom:
    osvscan:
      path: ./osvscan.so
      description: OSV vulnerability scanner
      settings:
        min-severity: 7.0  # Only HIGH and CRITICAL

linters:
  enable:
    - osvscan
```

Run:
```bash
golangci-lint run
```

## Common Use Cases

### Filter High Severity Only

```go
package main

import (
    "golang.org/x/tools/go/analysis/singlechecker"
    "github.com/garutyunov/osvscan"
)

func main() {
    analyzer := osvscan.NewAnalyzer(&osvscan.Settings{
        MinSeverity: 7.0, // HIGH and CRITICAL only
    })
    singlechecker.Main(analyzer)
}
```

### Ignore Specific Vulnerabilities

```go
analyzer := osvscan.NewAnalyzer(&osvscan.Settings{
    IgnoreVulns: []string{
        "CVE-2021-3121",
        "GHSA-xxxx-yyyy-zzzz",
    },
})
```

### Offline Mode

```go
analyzer := osvscan.NewAnalyzer(&osvscan.Settings{
    Offline:           true,
    LocalDBPath:       "/path/to/osv/db",
    DownloadDatabases: true,
})
```

## Testing

Run the test suite:

```bash
cd /home/garutyunov/go-scanner/osvscan
make test
```

## Build

Build the standalone tool:

```bash
make build
./cmd/osvscan/osvscan ./...
```

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Check [INTEGRATION.md](INTEGRATION.md) for golangci-lint integration
- Review [SUMMARY.md](SUMMARY.md) for implementation details

## Troubleshooting

### No vulnerabilities found but you expect some

- Ensure your `go.mod` is up to date: `go mod tidy`
- Verify network connectivity to OSV API
- Check that dependencies are properly declared

### Scanner fails with network error

- Enable offline mode
- Download OSV database locally
- Check firewall settings

### False positives

- Use `ignore-vulns` to exclude specific IDs
- Report issues to OSV database maintainers

## Support

For issues and questions:
- Check existing documentation
- Review test cases for examples
- File issues on GitHub

## Quick Reference

**Key Files:**
- `analyzer.go` - Core implementation
- `settings.go` - Configuration
- `linter.go` - golangci-lint integration
- `cmd/osvscan/main.go` - Standalone CLI

**Key Functions:**
- `osvscan.Analyzer` - Default analyzer instance
- `osvscan.NewAnalyzer(settings)` - Custom analyzer with settings
- `osvscan.New(settings)` - golangci-lint integration

**Settings:**
- `Offline bool` - Use local database
- `DownloadDatabases bool` - Auto-download DB
- `LocalDBPath string` - DB location
- `IgnoreVulns []string` - Ignore list
- `MinSeverity float64` - CVSS threshold (0-10)
