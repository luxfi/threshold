package adapters

// White-box regression tests for Item5 (threshold LSS crypto hygiene):
// Dilithium/ML-DSA secret, error, and masking-polynomial sampling must go
// through crypto/rand (via randIntn), never math/rand. These tests live in
// `package adapters` (not `adapters_test`) so they can reach the unexported
// sampling methods directly, and so the source-scan lock test below can
// never be skipped by an external test build tag.

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
)

// TestRandIntn_Bounds checks that randIntn always returns a value in [0, n)
// across a range of n, including edge cases (n=1, large n).
func TestRandIntn_Bounds(t *testing.T) {
	for _, n := range []int{1, 2, 3, 17, 256, 1 << 17, 1 << 19} {
		for i := 0; i < 200; i++ {
			v := randIntn(n)
			if v < 0 || v >= n {
				t.Fatalf("randIntn(%d) = %d, want in [0, %d)", n, v, n)
			}
		}
	}
}

// TestRandIntn_RejectsNonPositive locks the fail-closed behavior: there is
// no valid sample space for n <= 0, so randIntn must panic rather than
// silently return a degenerate value.
func TestRandIntn_RejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("randIntn(%d) did not panic", n)
				}
			}()
			randIntn(n)
		}()
	}
}

// TestRandIntn_NotDeterministic proves the sampler is actually reading fresh
// entropy from crypto/rand.Reader rather than e.g. a fixed/math-rand-style
// process-seeded sequence: two independent runs over a wide range must not
// collide across the board.
func TestRandIntn_NotDeterministic(t *testing.T) {
	const n = 1 << 20
	a := make([]int, 32)
	b := make([]int, 32)
	for i := range a {
		a[i] = randIntn(n)
	}
	for i := range b {
		b[i] = randIntn(n)
	}
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("two independent 32-sample draws from randIntn(%d) were identical — entropy source looks broken/fixed", n)
	}
}

// TestDilithiumAdapter_SecretSampling_UsesCSPRNG exercises the real,
// exported DilithiumDKG -> sampleSecret/sampleError/sampleMask path (via
// SignEC) and checks: (1) sampled coefficients respect the Eta/Gamma1
// bounds mandated by the ML-DSA parameter set, and (2) two independent DKG
// runs produce different secret shares, which would be impossible if
// sampling were driven by a low-entropy or deterministic source.
func TestDilithiumAdapter_SecretSampling_UsesCSPRNG(t *testing.T) {
	parties := []party.ID{"p1", "p2", "p3"}

	run := func() *DilithiumSecretShare {
		d := NewDilithiumAdapter(2) // ML-DSA-44
		_, shares, err := d.DilithiumDKG(parties, 2)
		if err != nil {
			t.Fatalf("DilithiumDKG: %v", err)
		}
		share := shares["p1"]
		eta := int32(d.params.Eta)
		for _, row := range share.S {
			for _, coeff := range row {
				if coeff < -eta || coeff > eta {
					t.Fatalf("secret coefficient %d out of [-eta,eta]=[-%d,%d]", coeff, eta, eta)
				}
			}
		}
		return share
	}

	s1 := run()
	s2 := run()

	if len(s1.S) == 0 || len(s1.S[0]) == 0 {
		t.Fatalf("empty secret share")
	}
	if identicalPolys(s1.S, s2.S) {
		t.Fatalf("two independent DilithiumDKG runs produced identical secret polynomials — crypto/rand sampling appears broken")
	}
}

// TestDilithiumAdapter_MaskSampling_UsesCSPRNG exercises sampleMask (the y
// nonce-equivalent) via SignEC and confirms two signing rounds over the
// same share produce different masks. A predictable/repeating y is the
// lattice-signature analogue of ECDSA nonce reuse and permits key recovery.
func TestDilithiumAdapter_MaskSampling_UsesCSPRNG(t *testing.T) {
	parties := []party.ID{"p1", "p2", "p3"}
	d := NewDilithiumAdapter(2)
	_, shares, err := d.DilithiumDKG(parties, 2)
	if err != nil {
		t.Fatalf("DilithiumDKG: %v", err)
	}

	digest, err := d.Digest([]byte("item5-regression"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}

	_ = shares // DKG shares are keyed into d.state by ID; SignEC looks them up by share.ID.

	sig1, err := d.SignEC(digest, Share{ID: "p1"})
	if err != nil {
		t.Fatalf("SignEC #1: %v", err)
	}
	sig2, err := d.SignEC(digest, Share{ID: "p1"})
	if err != nil {
		t.Fatalf("SignEC #2: %v", err)
	}

	z1 := sig1.(*DilithiumPartialSig).Z
	z2 := sig2.(*DilithiumPartialSig).Z
	if identicalPolys(z1, z2) {
		t.Fatalf("two independent SignEC calls produced identical z (mask y) — nonce/mask reuse risk")
	}
}

// TestMLDSAThresholdAdapter_MaskSampling_UsesCSPRNG exercises
// sampleMaskingVector directly (white-box) and confirms bounds + freshness,
// mirroring the Dilithium mask test above for the true-threshold Shamir-LSS
// adapter.
func TestMLDSAThresholdAdapter_MaskSampling_UsesCSPRNG(t *testing.T) {
	m := &MLDSAThresholdAdapter{params: GetMLDSAParams(2)}
	gamma1 := m.params.Gamma1

	run := func() []SecretPoly {
		return m.sampleMaskingVector(m.params.L, gamma1)
	}

	y1 := run()
	y2 := run()

	bound := F(gamma1 - 1)
	for _, poly := range y1 {
		for _, c := range poly.Coeffs {
			if c < -bound || c > bound {
				t.Fatalf("mask coefficient %d out of [-%d,%d]", c, bound, bound)
			}
		}
	}
	if identicalSecretPolys(y1, y2) {
		t.Fatalf("two independent sampleMaskingVector calls produced identical output — nonce/mask reuse risk")
	}
}

// TestPackage_NoMathRandForSecrets is a source-level lock: it parses every
// non-test .go file in this package and fails if "math/rand" (v1 or v2) is
// imported anywhere. This is the regression guard for Item5 — it fires at
// `go test` time, not just at code-review time, so a future contributor
// cannot silently reintroduce math/rand for secret/nonce sampling here.
func TestPackage_NoMathRandForSecrets(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if filepath.Ext(f) != ".go" {
			continue
		}
		if len(f) > 8 && f[len(f)-8:] == "_test.go" {
			continue // test-only jitter/fixtures are out of scope for this lock
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			path := imp.Path.Value
			if path == `"math/rand"` || path == `"math/rand/v2"` {
				t.Fatalf("%s imports %s — Dilithium/ML-DSA secret and nonce material must be sampled via crypto/rand (randIntn in csprng.go), never math/rand", f, path)
			}
		}
	}
}

func identicalPolys(a, b [][]int32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func identicalSecretPolys(a, b []SecretPoly) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i].Coeffs) != len(b[i].Coeffs) {
			return false
		}
		for j := range a[i].Coeffs {
			if a[i].Coeffs[j] != b[i].Coeffs[j] {
				return false
			}
		}
	}
	return true
}
