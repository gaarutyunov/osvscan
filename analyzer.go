package osvscan

import (
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

const linterName = "osvscan"

// Analyzer is the osvscan analyzer that checks for vulnerabilities in dependencies.
var Analyzer = &analysis.Analyzer{
	Name: linterName,
	Doc:  "reports vulnerabilities in Go module dependencies using osv-scanner",
	Run:  run,
}

// NewAnalyzer creates a new analyzer with the given settings.
func NewAnalyzer(settings *Settings) *analysis.Analyzer {
	if settings == nil {
		settings = &Settings{}
	}

	return &analysis.Analyzer{
		Name: linterName,
		Doc:  "reports vulnerabilities in Go module dependencies using osv-scanner",
		Run: func(pass *analysis.Pass) (interface{}, error) {
			return runWithSettings(pass, settings)
		},
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	return runWithSettings(pass, &Settings{})
}

func runWithSettings(pass *analysis.Pass, settings *Settings) (interface{}, error) {
	// Get the package path
	pkgPath := pass.Pkg.Path()
	if pkgPath == "" {
		return nil, nil
	}

	// Find the module root by looking for go.mod
	moduleRoot, err := findModuleRoot(pass)
	if err != nil {
		// If we can't find the module root, skip silently
		return nil, nil
	}

	goModPath := filepath.Join(moduleRoot, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		// No go.mod file, nothing to scan
		return nil, nil
	}

	// Perform the OSV scan
	vulnResult, err := scanModule(moduleRoot, settings)
	if err != nil {
		// Log error but don't fail the analysis
		return nil, nil
	}

	// Get position for reporting (prefer go.mod if available, otherwise first file)
	pos := getReportPosition(pass, goModPath)

	// Report vulnerabilities
	reportVulnerabilities(pass, vulnResult, pos, settings)

	return nil, nil
}

// findModuleRoot finds the module root directory by traversing up from the package.
func findModuleRoot(pass *analysis.Pass) (string, error) {
	// Try to get a file from the package to determine the directory
	if len(pass.Files) == 0 {
		return "", fmt.Errorf("no files in package")
	}

	// Get the first file's position
	firstFile := pass.Files[0]
	filePos := pass.Fset.Position(firstFile.Pos())
	if filePos.Filename == "" {
		return "", fmt.Errorf("no filename available")
	}

	// Start from the directory containing the file
	dir := filepath.Dir(filePos.Filename)

	// Traverse up to find go.mod
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root without finding go.mod
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

// scanModule performs the OSV scan on the module.
func scanModule(moduleRoot string, settings *Settings) (*models.VulnerabilityResults, error) {
	// Configure the scanner based on settings
	r := &osvscanner.ScannerActions{
		LockfilePaths:     []string{filepath.Join(moduleRoot, "go.mod")},
		DirectoryPaths:    []string{moduleRoot},
		SkipGit:           true,
		Recursive:         false,
		CompareOffline:    settings.Offline,
		DownloadDatabases: settings.DownloadDatabases,
		LocalDBPath:       settings.LocalDBPath,
	}

	// Perform the scan
	vulnResult, err := osvscanner.DoScan(r, nil)
	if err != nil {
		return nil, fmt.Errorf("osv scan failed: %w", err)
	}

	return vulnResult, nil
}

// getReportPosition determines the position to report diagnostics.
func getReportPosition(pass *analysis.Pass, goModPath string) token.Pos {
	// Try to find go.mod in the file set
	for _, file := range pass.Files {
		pos := pass.Fset.Position(file.Pos())
		if strings.HasSuffix(pos.Filename, "go.mod") {
			return file.Pos()
		}
	}

	// If go.mod is not in the AST, use the first Go file
	if len(pass.Files) > 0 {
		return pass.Files[0].Pos()
	}

	// Fallback to invalid position
	return token.NoPos
}

// reportVulnerabilities reports each vulnerability as a diagnostic.
func reportVulnerabilities(pass *analysis.Pass, vulnResult *models.VulnerabilityResults, pos token.Pos, settings *Settings) {
	if vulnResult == nil || len(vulnResult.Results) == 0 {
		return
	}

	for _, result := range vulnResult.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				// Check if vulnerability should be ignored
				if shouldIgnoreVulnerability(vuln, settings) {
					continue
				}

				message := formatVulnerabilityMessage(vuln, pkg)
				pass.Report(analysis.Diagnostic{
					Pos:     pos,
					Message: message,
				})
			}
		}
	}
}

// shouldIgnoreVulnerability checks if a vulnerability should be ignored based on settings.
func shouldIgnoreVulnerability(vuln models.Vulnerability, settings *Settings) bool {
	// Check if vulnerability ID is in ignore list
	for _, ignored := range settings.IgnoreVulns {
		if vuln.ID == ignored {
			return true
		}
	}

	// Check minimum severity
	if settings.MinSeverity > 0 {
		severity := getVulnerabilitySeverity(vuln)
		if severity < settings.MinSeverity {
			return true
		}
	}

	return false
}

// getVulnerabilitySeverity extracts the CVSS score from a vulnerability.
func getVulnerabilitySeverity(vuln models.Vulnerability) float64 {
	// Try to get CVSS score from the vulnerability
	if len(vuln.Affected) > 0 {
		for _, sev := range vuln.Affected[0].Severity {
			if sev.Type == "CVSS_V3" {
				return sev.Score
			}
		}
	}
	return 0.0
}

// formatVulnerabilityMessage creates a diagnostic message from a vulnerability.
func formatVulnerabilityMessage(vuln models.Vulnerability, pkg models.PackageVulns) string {
	var severity string
	if len(vuln.Affected) > 0 && len(vuln.Affected[0].DatabaseSpecific.Severity) > 0 {
		severity = vuln.Affected[0].DatabaseSpecific.Severity
	} else {
		severity = "UNKNOWN"
	}

	summary := vuln.Summary
	if summary == "" {
		summary = "No summary available"
	}

	return fmt.Sprintf("[%s] %s in %s@%s: %s",
		severity,
		vuln.ID,
		pkg.Package.Name,
		pkg.Package.Version,
		summary,
	)
}
