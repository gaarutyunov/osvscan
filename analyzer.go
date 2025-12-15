package osvscan

import (
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/tools/go/analysis"
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
	pkgPath := pass.Pkg.Path()
	if pkgPath == "" {
		return nil, nil
	}

	moduleRoot, err := findModuleRoot(pass)
	if err != nil {
		return nil, nil
	}

	goModPath := filepath.Join(moduleRoot, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		return nil, nil
	}

	vulnResult, err := scanModule(moduleRoot, settings)
	if err != nil {
		return nil, nil
	}

	pos := getReportPosition(pass, goModPath)
	reportVulnerabilities(pass, vulnResult, pos, settings)

	return nil, nil
}

func findModuleRoot(pass *analysis.Pass) (string, error) {
	if len(pass.Files) == 0 {
		return "", fmt.Errorf("no files in package")
	}

	firstFile := pass.Files[0]
	filePos := pass.Fset.Position(firstFile.Pos())
	if filePos.Filename == "" {
		return "", fmt.Errorf("no filename available")
	}

	dir := filepath.Dir(filePos.Filename)

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

func scanModule(moduleRoot string, settings *Settings) (models.VulnerabilityResults, error) {
	r := osvscanner.ScannerActions{
		LockfilePaths:     []string{filepath.Join(moduleRoot, "go.mod")},
		DirectoryPaths:    []string{moduleRoot},
		Recursive:         false,
		CompareOffline:    settings.Offline,
		DownloadDatabases: settings.DownloadDatabases,
		LocalDBPath:       settings.LocalDBPath,
	}

	return osvscanner.DoScan(r)
}

func getReportPosition(pass *analysis.Pass, goModPath string) token.Pos {
	for _, file := range pass.Files {
		pos := pass.Fset.Position(file.Pos())
		if strings.HasSuffix(pos.Filename, "go.mod") {
			return file.Pos()
		}
	}

	if len(pass.Files) > 0 {
		return pass.Files[0].Pos()
	}

	return token.NoPos
}

func reportVulnerabilities(pass *analysis.Pass, vulnResult models.VulnerabilityResults, pos token.Pos, settings *Settings) {
	if len(vulnResult.Results) == 0 {
		return
	}

	for _, result := range vulnResult.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
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

func shouldIgnoreVulnerability(vuln *osvschema.Vulnerability, settings *Settings) bool {
	for _, ignored := range settings.IgnoreVulns {
		if vuln.GetId() == ignored {
			return true
		}
	}

	if settings.MinSeverity > 0 {
		severity := getVulnerabilitySeverity(vuln)
		if severity < settings.MinSeverity {
			return true
		}
	}

	return false
}

func getVulnerabilitySeverity(vuln *osvschema.Vulnerability) float64 {
	if len(vuln.Severity) > 0 {
		for _, sev := range vuln.Severity {
			if sev.Type == osvschema.SeverityType_SEVERITY_TYPE_CVSS_V3 {
				return sev.Score
			}
		}
	}
	return 0.0
}

func formatVulnerabilityMessage(vuln *osvschema.Vulnerability, pkg models.PackageVulns) string {
	severity := "UNKNOWN"
	if len(vuln.Severity) > 0 {
		for _, sev := range vuln.Severity {
			if sev.Type == osvschema.SeverityType_SEVERITY_TYPE_CVSS_V3 {
				if sev.Score >= 9.0 {
					severity = "CRITICAL"
				} else if sev.Score >= 7.0 {
					severity = "HIGH"
				} else if sev.Score >= 4.0 {
					severity = "MEDIUM"
				} else {
					severity = "LOW"
				}
				break
			}
		}
	}

	summary := vuln.Summary
	if summary == "" {
		summary = "No summary available"
	}

	return fmt.Sprintf("[%s] %s in %s@%s: %s",
		severity,
		vuln.GetId(),
		pkg.Package.Name,
		pkg.Package.Version,
		summary,
	)
}
