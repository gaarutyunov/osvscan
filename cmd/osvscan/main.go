package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/garutyunov/osvscan"
)

func main() {
	singlechecker.Main(osvscan.Analyzer)
}
