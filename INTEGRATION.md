# Integration Guide

## Integrating osvscan with golangci-lint

This analyzer can be integrated into golangci-lint as a custom linter.

### Option 1: Using golangci-lint plugins

1. Build the analyzer as a plugin:

```bash
go build -buildmode=plugin -o osvscan.so
```

2. Configure golangci-lint to load the plugin:

```yaml
# .golangci.yml
linters-settings:
  custom:
    osvscan:
      path: /path/to/osvscan.so
      description: OSV vulnerability scanner
      original-url: github.com/garutyunov/osvscan
```

### Option 2: Fork and integrate directly

1. Fork golangci-lint repository

2. Add the analyzer to the linters manager:

```go
// pkg/golinters/osvscan.go
package golinters

import (
	"github.com/garutyunov/osvscan"
	"golang.org/x/tools/go/analysis"
)

func NewOSVScan() *goanalysis.Linter {
	return goanalysis.NewLinter(
		"osvscan",
		"OSV vulnerability scanner for Go dependencies",
		[]*analysis.Analyzer{osvscan.Analyzer},
		nil,
	).WithLoadMode(goanalysis.LoadModeSyntax)
}
```

3. Register in the linters manager:

```go
// pkg/lint/lintersdb/manager.go
func (m *Manager) GetAllSupportedLinterConfigs() []*linter.Config {
	// ... existing linters ...
	linters = append(linters, golinters.NewOSVScan())
	// ...
}
```

### Option 3: Use as standalone tool

Run the analyzer directly on your code:

```bash
go run ./cmd/osvscan ./...
```

Or install it:

```bash
go install github.com/garutyunov/osvscan/cmd/osvscan@latest
osvscan ./...
```

## Configuration

The analyzer runs with default settings and scans the go.mod file in your module.

### Customization

To customize the analyzer behavior, you can modify the `ScannerActions` in `analyzer.go`:

```go
r := &osvscanner.ScannerActions{
	LockfilePaths:    []string{filepath.Join(moduleRoot, "go.mod")},
	DirectoryPaths:   []string{moduleRoot},
	SkipGit:          true,
	Recursive:        false,
	CompareOffline:   false, // Set to true to use cached data
	ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
		CompareLocalDB: "/path/to/local/db", // Optional local DB
	},
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  osvscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - name: Install osvscan
        run: go install github.com/garutyunov/osvscan/cmd/osvscan@latest
      - name: Run security scan
        run: osvscan ./...
```

### GitLab CI

```yaml
osvscan:
  image: golang:1.24
  script:
    - go install github.com/garutyunov/osvscan/cmd/osvscan@latest
    - osvscan ./...
  only:
    - merge_requests
    - main
```

## Troubleshooting

### No vulnerabilities found

- Ensure your project has a valid `go.mod` file
- Check that dependencies are properly declared
- Verify network connectivity to OSV database

### Analyzer not reporting in golangci-lint

- Ensure the plugin is built correctly
- Verify the path in `.golangci.yml` is correct
- Check golangci-lint logs for plugin loading errors

### Performance considerations

- The analyzer makes network requests to OSV database
- Consider caching results in CI/CD pipelines
- Use `CompareOffline: true` with a local database for faster scans
