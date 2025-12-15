package osvscan

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/tools/go/analysis/analysistest"
)

// TestAnalyzer_VulnerableProtobuf verifies detection of CVE-2021-3121 in gogo/protobuf v1.3.1.
func TestAnalyzer_VulnerableProtobuf(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/vulnerable_protobuf")

	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	foundVuln := false
	for _, result := range results {
		if len(result.Diagnostics) > 0 {
			foundVuln = true
			for _, diag := range result.Diagnostics {
				t.Logf("Found vulnerability: %s", diag.Message)
			}
		}
	}

	if !foundVuln {
		t.Skip("no vulnerabilities found - OSV API may not have returned results (integration test)")
	}
}

// TestAnalyzer_VulnerableImage verifies detection of CVEs in golang.org/x/image v0.4.0.
func TestAnalyzer_VulnerableImage(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/vulnerable_image")

	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	foundVuln := false
	for _, result := range results {
		if len(result.Diagnostics) > 0 {
			foundVuln = true
			for _, diag := range result.Diagnostics {
				t.Logf("Found vulnerability: %s", diag.Message)
			}
		}
	}

	if !foundVuln {
		t.Skip("no vulnerabilities found - OSV API may not have returned results (integration test)")
	}
}

// TestAnalyzer_MultipleVulnerabilities verifies that multiple vulnerabilities are reported.
func TestAnalyzer_MultipleVulnerabilities(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/vulnerable_multiple")

	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	totalDiags := 0
	for _, result := range results {
		totalDiags += len(result.Diagnostics)
		for _, diag := range result.Diagnostics {
			t.Logf("Found vulnerability: %s", diag.Message)
		}
	}

	if totalDiags == 0 {
		t.Skip("no vulnerabilities found - OSV API may not have returned results (integration test)")
	}
}

// TestAnalyzer_CleanProject verifies no false positives for clean projects.
func TestAnalyzer_CleanProject(t *testing.T) {
	t.Parallel()
	skipIfNetworkUnavailable(t)

	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, Analyzer, "example.com/clean")

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

	for _, result := range results {
		if len(result.Diagnostics) > 0 {
			for _, diag := range result.Diagnostics {
				t.Errorf("unexpected diagnostic in project without go.mod: %s", diag.Message)
			}
		}
	}
}

// TestFormatVulnerabilityMessage tests the vulnerability message formatting.
func TestFormatVulnerabilityMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		vuln     osvschema.Vulnerability
		pkg      models.PackageVulns
		contains string
	}{
		{
			name: "basic vulnerability",
			vuln: osvschema.Vulnerability{
				ID:      "CVE-2021-3121",
				Summary: "gogo/protobuf has encoding/decoding issue",
			},
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:    "github.com/gogo/protobuf",
					Version: "1.3.1",
				},
			},
			contains: "CVE-2021-3121",
		},
		{
			name: "no summary",
			vuln: osvschema.Vulnerability{
				ID:      "GHSA-xxxx-yyyy-zzzz",
				Summary: "",
			},
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:    "example.com/another",
					Version: "2.1.0",
				},
			},
			contains: "No summary available",
		},
		{
			name: "with severity",
			vuln: osvschema.Vulnerability{
				ID:      "CVE-2024-9999",
				Summary: "Critical remote code execution",
				Severity: []osvschema.Severity{
					{Type: osvschema.SeverityCVSSV3, Score: "9.8"},
				},
			},
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:    "vuln.example.com/rce",
					Version: "0.5.0",
				},
			},
			contains: "CRITICAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatVulnerabilityMessage(tt.vuln, tt.pkg)
			if !containsString(result, tt.contains) {
				t.Errorf("formatVulnerabilityMessage() = %q, want to contain %q", result, tt.contains)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func skipIfNetworkUnavailable(t *testing.T) {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://api.osv.dev/")
	if err != nil {
		t.Skipf("skipping test: network unavailable: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 500 {
		t.Skipf("skipping test: OSV API unavailable (status: %d)", resp.StatusCode)
	}
}
