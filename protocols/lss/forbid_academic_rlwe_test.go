// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Regression guard for the LSS-Pulsar / LSS-Lens adapters. The
// production R-LWE path is luxfi/corona; the Module-LWE Threshold
// path is luxfi/pulsar; the academic upstream forks (luxfi/ringtail,
// luxfi/nasua) are research-only and MUST NOT appear in production
// import graphs.
//
// This test fails CI if either lss_pulsar.go or lss_lens.go imports
// any of the academic-fork module paths directly. Other files in
// this package are out of scope.

package lss

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLSSAdaptersForbidAcademicRLWE — fails if either lss_pulsar.go
// or lss_lens.go imports an academic-fork R-LWE library directly.
// Production R-LWE goes through luxfi/corona; Module-LWE Threshold
// goes through luxfi/pulsar.
func TestLSSAdaptersForbidAcademicRLWE(t *testing.T) {
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	files := []string{"lss_pulsar.go", "lss_lens.go"}

	forbiddenPrefixes := []string{
		"github.com/luxfi/ringtail",
		"github.com/luxfi/nasua",
	}

	fset := token.NewFileSet()
	var violations []string
	for _, base := range files {
		path := filepath.Join(pkgDir, base)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", base, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports %s: %v", base, err)
		}
		for _, imp := range file.Imports {
			ip := strings.Trim(imp.Path.Value, "\"")
			for _, forbidden := range forbiddenPrefixes {
				if strings.HasPrefix(ip, forbidden) {
					violations = append(violations,
						base+": forbidden import "+ip)
				}
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("LSS adapters must not import academic-fork R-LWE "+
			"libraries directly. Production R-LWE = luxfi/corona; "+
			"production Module-LWE Threshold = luxfi/pulsar.\n\n"+
			"Violations:\n  %s", strings.Join(violations, "\n  "))
	}
}
