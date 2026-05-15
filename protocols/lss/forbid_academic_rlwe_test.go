// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Death test for the LSS-Pulsar / LSS-Lens adapters. After the
// March 3, 2026 PQ-consensus architecture freeze, the LSS adapters
// consume their threshold kernels via:
//
//   - lss_pulsar.go → github.com/luxfi/pulsar
//   - lss_lens.go   → github.com/luxfi/lens
//
// Direct imports of github.com/luxfi/corona from either adapter
// are forbidden — they bypass the Pulsar key-era binding /
// activation cert circuit-breaker that LSS-Pulsar wires in. Other
// files in this package may still legitimately use corona (e.g.
// the corona-specific protocol entry-points under
// protocols/corona/ aren't covered by this test); this test
// scopes the rule to the two adapter files only.

package lss

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLSSAdaptersDoNotImportCorona — fails if either lss_pulsar.go
// or lss_lens.go imports github.com/luxfi/corona/... directly.
func TestLSSAdaptersDoNotImportCorona(t *testing.T) {
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	files := []string{"lss_pulsar.go", "lss_lens.go"}

	const forbiddenImportPrefix = "github.com/luxfi/corona"

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
			if strings.HasPrefix(ip, forbiddenImportPrefix) {
				violations = append(violations,
					base+": forbidden import "+ip)
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("LSS adapters must not import corona directly after "+
			"the Mar-3-2026 PQ-consensus architecture freeze. "+
			"lss_pulsar.go MUST go through github.com/luxfi/pulsar; "+
			"lss_lens.go MUST go through github.com/luxfi/lens.\n\n"+
			"Violations:\n  %s", strings.Join(violations, "\n  "))
	}
}
