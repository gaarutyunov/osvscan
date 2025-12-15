# osvscan

[![CI](https://github.com/gaarutyunov/osvscan/actions/workflows/ci.yml/badge.svg)](https://github.com/gaarutyunov/osvscan/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/gaarutyunov/osvscan)](https://goreportcard.com/report/github.com/gaarutyunov/osvscan)
[![Go Reference](https://pkg.go.dev/badge/github.com/gaarutyunov/osvscan.svg)](https://pkg.go.dev/github.com/gaarutyunov/osvscan)

A go/analysis linter that scans Go module dependencies for known vulnerabilities using [osv-scanner](https://github.com/google/osv-scanner).

## Installation

```bash
go install github.com/gaarutyunov/osvscan/cmd/osvscan@latest
```

## Usage

### Standalone

```bash
osvscan ./...
```

### With golangci-lint

Add to your `.golangci.yml`:

```yaml
linters:
  enable:
    - osvscan

linters-settings:
  osvscan:
    offline: false
    download-databases: false
    local-db-path: ""
    ignore-vulns: []
    min-severity: 0
```

### As a Library

```go
package main

import (
    "golang.org/x/tools/go/analysis/singlechecker"
    "github.com/gaarutyunov/osvscan"
)

func main() {
    singlechecker.Main(osvscan.Analyzer)
}
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `offline` | bool | `false` | Enable offline scanning using local database |
| `download-databases` | bool | `false` | Download offline databases when in offline mode |
| `local-db-path` | string | `""` | Path for local vulnerability database |
| `ignore-vulns` | []string | `[]` | List of vulnerability IDs to ignore (GHSA, CVE) |
| `min-severity` | float | `0` | Filter vulnerabilities below this CVSS score (0-10) |

## Examples

### Filter High Severity Only

```yaml
linters-settings:
  osvscan:
    min-severity: 7.0
```

### Ignore Specific Vulnerabilities

```yaml
linters-settings:
  osvscan:
    ignore-vulns:
      - "GHSA-xxxx-xxxx-xxxx"
      - "CVE-2023-12345"
```

### Offline Mode

```yaml
linters-settings:
  osvscan:
    offline: true
    download-databases: true
```

## Output

```
go.mod:1:1: [HIGH] GHSA-xxxx-xxxx-xxxx in github.com/example/pkg@v1.2.3: Vulnerability description
```

## License

MIT
