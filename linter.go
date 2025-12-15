package osvscan

import (
	"github.com/golangci/golangci-lint/v2/pkg/goanalysis"
)

// New creates a new osvscan linter for golangci-lint
func New(settings *Settings) *goanalysis.Linter {
	return goanalysis.
		NewLinterFromAnalyzer(NewAnalyzer(settings)).
		WithLoadMode(goanalysis.LoadModeSyntax)
}
