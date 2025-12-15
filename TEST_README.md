# OSV Scanner Analyzer Tests

This directory contains integration tests for the OSV scanner analyzer, which detects vulnerabilities in Go module dependencies.

## Test Structure

The tests use the `golang.org/x/tools/go/analysis/analysistest` package to run the analyzer against test data directories.

### Test Files

- `analyzer.go` - The main analyzer implementation
- `analyzer_test.go` - Integration and unit tests for the analyzer

### Test Data Directories

The `testdata/` directory contains sample projects used for testing:

1. **vulnerable_protobuf/** - Tests CVE-2021-3121 detection
   - Contains `github.com/gogo/protobuf v1.3.1` (known vulnerable version)
   - Expected: Should report vulnerabilities

2. **vulnerable_image/** - Tests CVE detection in golang.org/x/image
   - Contains `golang.org/x/image v0.4.0` (known vulnerable version)
   - Expected: Should report vulnerabilities

3. **vulnerable_multiple/** - Tests multiple vulnerability detection
   - Contains both vulnerable packages mentioned above
   - Expected: Should report multiple vulnerabilities

4. **clean/** - Tests for false positives
   - Contains only standard library imports
   - Expected: No vulnerabilities should be reported

5. **no_gomod/** - Tests graceful handling of missing go.mod
   - No go.mod file present
   - Expected: Should complete without error, no diagnostics

## Running the Tests

### Run All Tests
```bash
cd /home/garutyunov/go-scanner/osvscan
go test -v
```

### Run Specific Test
```bash
go test -v -run TestAnalyzer_VulnerableProtobuf
```

### Run Only Unit Tests (No Network Required)
```bash
go test -v -run TestFormatVulnerabilityMessage
```

### Run with Parallel Execution
```bash
go test -v -parallel 4
```

## Test Descriptions

### Integration Tests

#### TestAnalyzer_VulnerableProtobuf
Verifies that the analyzer correctly detects CVE-2021-3121 in gogo/protobuf v1.3.1.

**Purpose**: Ensure the analyzer can detect known vulnerabilities in commonly used packages.

**Network**: Required (uses OSV API)

#### TestAnalyzer_VulnerableImage
Verifies that the analyzer detects CVEs in golang.org/x/image v0.4.0.

**Purpose**: Test vulnerability detection in official Go packages.

**Network**: Required (uses OSV API)

#### TestAnalyzer_MultipleVulnerabilities
Verifies that multiple vulnerabilities are correctly reported when a project has multiple vulnerable dependencies.

**Purpose**: Ensure all vulnerabilities are found, not just the first one.

**Network**: Required (uses OSV API)

#### TestAnalyzer_CleanProject
Verifies that no false positives are reported for projects without vulnerable dependencies.

**Purpose**: Ensure the analyzer doesn't report spurious vulnerabilities.

**Network**: Required (uses OSV API)

#### TestAnalyzer_NoGoMod
Verifies graceful handling when no go.mod file exists.

**Purpose**: Ensure the analyzer doesn't crash on projects without go.mod.

**Network**: Not required

### Unit Tests

#### TestFormatVulnerabilityMessage
Tests the `formatVulnerabilityMessage` function with various inputs.

**Test Cases**:
- Full vulnerability information (severity, summary, CVE ID)
- Missing severity (should default to "UNKNOWN")
- Missing summary (should use "No summary available")
- Various severity levels (HIGH, MEDIUM, CRITICAL)

**Purpose**: Ensure vulnerability messages are formatted correctly.

**Network**: Not required

## Network Requirements

Most integration tests require network access to the OSV API (`https://api.osv.dev/`). Tests automatically skip if:
- Network is unavailable
- OSV API is unreachable
- OSV API returns server errors (5xx)

The `skipIfNetworkUnavailable` helper function checks connectivity before running network-dependent tests.

## Test Best Practices

1. **Parallel Execution**: Tests use `t.Parallel()` where safe to improve execution time
2. **Network Checks**: Network-dependent tests check connectivity before running
3. **Helpful Logging**: Tests log found vulnerabilities for debugging
4. **Clear Assertions**: Tests have descriptive error messages explaining what went wrong

## Troubleshooting

### Tests Skip Due to Network Issues
If you see "skipping test: network unavailable", ensure:
- You have internet connectivity
- The OSV API (`https://api.osv.dev/`) is accessible
- Your firewall allows HTTPS connections

### Tests Fail to Find Vulnerabilities
If vulnerability detection tests fail:
1. Check if the vulnerable versions still have known CVEs in the OSV database
2. Verify go.sum files exist (run `go mod download` in test directories)
3. Check OSV scanner logs for API errors

### Tests Timeout
If tests take too long:
- Run with `-timeout` flag: `go test -timeout 5m`
- Check network latency to OSV API
- Run tests serially instead of parallel

## Updating Test Data

To update vulnerable package versions:

```bash
cd testdata/vulnerable_protobuf
go get github.com/gogo/protobuf@v1.3.1
go mod tidy
```

To verify a package is still vulnerable:
```bash
cd testdata/vulnerable_protobuf
osv-scanner --lockfile=go.mod
```

## CI/CD Considerations

When running in CI/CD:
- Ensure network access to `api.osv.dev`
- Consider caching OSV database for faster runs
- Use appropriate timeouts (recommended: 5 minutes)
- Run with `-v` flag for better debugging

Example CI command:
```bash
go test -v -timeout 5m -parallel 4 ./osvscan/...
```
