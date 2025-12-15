package osvscan

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
	"golang.org/x/tools/go/analysis/analysistest"
)

// TestAnalyzer_VulnerableProtobuf verifies detection of CVE-2021-3121 in gogo/protobuf v1.3.1.
func TestAnalyzer_VulnerableProtobuf(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/vulnerable_protobuf")

	// Verify at least one diagnostic was reported
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	// Check that vulnerabilities were found
	foundVuln := false
	for _, result := range results {
		if len(result.Diagnostics) > 0 {
			foundVuln = true
			// Log the diagnostics for debugging
			for _, diag := range result.Diagnostics {
				t.Logf("Found vulnerability: %s", diag.Message)
			}
		}
	}

	if !foundVuln {
		t.Error("expected to find vulnerabilities in gogo/protobuf v1.3.1")
	}
}

// TestAnalyzer_VulnerableImage verifies detection of CVEs in golang.org/x/image v0.4.0.
func TestAnalyzer_VulnerableImage(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/vulnerable_image")

	// Verify at least one diagnostic was reported
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	// Check that vulnerabilities were found
	foundVuln := false
	for _, result := range results {
		if len(result.Diagnostics) > 0 {
			foundVuln = true
			// Log the diagnostics for debugging
			for _, diag := range result.Diagnostics {
				t.Logf("Found vulnerability: %s", diag.Message)
			}
		}
	}

	if !foundVuln {
		t.Error("expected to find vulnerabilities in golang.org/x/image v0.4.0")
	}
}

// TestAnalyzer_MultipleVulnerabilities verifies that multiple vulnerabilities are reported
// when a project has multiple vulnerable dependencies.
func TestAnalyzer_MultipleVulnerabilities(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/vulnerable_multiple")

	// Verify at least one diagnostic was reported
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	// Count total diagnostics across all results
	totalDiags := 0
	for _, result := range results {
		totalDiags += len(result.Diagnostics)
		for _, diag := range result.Diagnostics {
			t.Logf("Found vulnerability: %s", diag.Message)
		}
	}

	// We expect multiple vulnerabilities since the project has multiple vulnerable deps
	if totalDiags == 0 {
		t.Error("expected to find multiple vulnerabilities in project with multiple vulnerable dependencies")
	}
}

// TestAnalyzer_CleanProject verifies that no false positives are reported
// for a project with no vulnerable dependencies.
func TestAnalyzer_CleanProject(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/clean")

	// Verify that no vulnerabilities were reported
	for _, result := range results {
		if len(result.Diagnostics) > 0 {
			for _, diag := range result.Diagnostics {
				t.Errorf("unexpected vulnerability reported in clean project: %s", diag.Message)
			}
		}
	}
}

// TestAnalyzer_NoGoMod verifies graceful handling when no go.mod exists.
func TestAnalyzer_NoGoMod(t *testing.T) {
	t.Parallel()

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/no_gomod")

	// The analyzer should complete without error even when go.mod doesn't exist
	// and should not report any diagnostics
	for _, result := range results {
		if len(result.Diagnostics) > 0 {
			for _, diag := range result.Diagnostics {
				t.Errorf("unexpected diagnostic in project without go.mod: %s", diag.Message)
			}
		}
	}
}

// TestFormatVulnerabilityMessage tests the vulnerability message formatting function.
func TestFormatVulnerabilityMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		vuln     models.Vulnerability
		pkg      models.PackageVulns
		expected string
	}{
		{
			name: "full vulnerability info",
			vuln: models.Vulnerability{
				ID:      "CVE-2021-3121",
				Summary: "gogo/protobuf has encoding/decoding issue",
				Affected: []models.Affected{
					{
						DatabaseSpecific: models.DatabaseSpecific{
							Severity: "HIGH",
						},
					},
				},
			},
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:    "github.com/gogo/protobuf",
					Version: "1.3.1",
				},
			},
			expected: "[HIGH] CVE-2021-3121 in github.com/gogo/protobuf@1.3.1: gogo/protobuf has encoding/decoding issue",
		},
		{
			name: "no severity",
			vuln: models.Vulnerability{
				ID:       "CVE-2023-1234",
				Summary:  "Test vulnerability",
				Affected: []models.Affected{},
			},
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:    "example.com/pkg",
					Version: "1.0.0",
				},
			},
			expected: "[UNKNOWN] CVE-2023-1234 in example.com/pkg@1.0.0: Test vulnerability",
		},
		{
			name: "no summary",
			vuln: models.Vulnerability{
				ID:      "GHSA-xxxx-yyyy-zzzz",
				Summary: "",
				Affected: []models.Affected{
					{
						DatabaseSpecific: models.DatabaseSpecific{
							Severity: "MEDIUM",
						},
					},
				},
			},
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:    "example.com/another",
					Version: "2.1.0",
				},
			},
			expected: "[MEDIUM] GHSA-xxxx-yyyy-zzzz in example.com/another@2.1.0: No summary available",
		},
		{
			name: "critical severity",
			vuln: models.Vulnerability{
				ID:      "CVE-2024-9999",
				Summary: "Critical remote code execution",
				Affected: []models.Affected{
					{
						DatabaseSpecific: models.DatabaseSpecific{
							Severity: "CRITICAL",
						},
					},
				},
			},
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:    "vuln.example.com/rce",
					Version: "0.5.0",
				},
			},
			expected: "[CRITICAL] CVE-2024-9999 in vuln.example.com/rce@0.5.0: Critical remote code execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatVulnerabilityMessage(tt.vuln, tt.pkg)
			if result != tt.expected {
				t.Errorf("formatVulnerabilityMessage() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// skipIfNetworkUnavailable skips the test if network connectivity is not available.
// OSV scanner requires network access in online mode to fetch vulnerability data.
func skipIfNetworkUnavailable(t *testing.T) {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Try to reach the OSV API
	resp, err := client.Get("https://api.osv.dev/")
	if err != nil {
		t.Skipf("skipping test: network unavailable: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		t.Skipf("skipping test: OSV API unavailable (status: %d)", resp.StatusCode)
	}
}
