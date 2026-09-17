// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// crsSeed is fixed for the tests. Consensus supplies it in production.
var crsSeed = []byte("lux-fchain-tfhe-dealerless-dkg-test-crs-seed-v1")

// Keygen, encrypt under the collective key, partial-decrypt, combine.

// TestKeygen runs the flow at PN10QP27.
func TestKeygen(t *testing.T) {
	for _, value := range []bool{false, true} {
		roundTrip(t, fhe.PN10QP27, 2, 3, value)
	}
}

// TestCommittee covers a larger committee at PN11QP54.
func TestCommittee(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3-of-5 dealerless round-trip under -short")
	}
	for _, value := range []bool{false, true} {
		roundTrip(t, fhe.PN11QP54, 3, 5, value)
	}
}

func roundTrip(t *testing.T, lit fhe.ParametersLiteral, threshold, total int, value bool) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatalf("params: %v", err)
	}

	// DEALERLESS key generation: no trusted dealer ever holds the FHE secret.
	pub, shares, err := Keygen(params, threshold, total, crsSeed)
	if err != nil {
		t.Fatalf("dealerless keygen: %v", err)
	}
	if len(shares) != total {
		t.Fatalf("share count: got %d want %d", len(shares), total)
	}
	if pub == nil || pub.PKLWE == nil {
		t.Fatalf("nil collective public key")
	}

	// Encrypt under the collective public key, with no secret key present.
	enc := fhe.NewBitwisePublicEncryptor(params, pub)
	ct, err := enc.Encrypt(value)
	if err != nil {
		t.Fatalf("public-key encrypt: %v", err)
	}

	// Threshold decrypt with the LAST t parties (avoids lucky small-Lagrange
	// alignment with the first shares).
	subset := shares[total-threshold:]
	partials := make([]*Partial, threshold)
	for i := range subset {
		share := subset[i]
		prng, err := sampling.NewPRNG()
		if err != nil {
			t.Fatalf("prng: %v", err)
		}
		p, err := share.Partial(ct, params, threshold, prng)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		partials[i] = p
	}

	got, err := Combine(ct, partials, params)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if got != value {
		t.Fatalf("dealerless round trip: got %v want %v (%d-of-%d)", got, value, threshold, total)
	}
}

// TestLone checks one partial decryption does not recover the plaintext.
func TestLone(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	pub, shares, err := Keygen(params, 2, 3, crsSeed)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	enc := fhe.NewBitwisePublicEncryptor(params, pub)

	disagreements := 0
	trials := 32
	share := shares[0]
	for i := 0; i < trials; i++ {
		value := i&1 == 0
		ct, err := enc.Encrypt(value)
		if err != nil {
			t.Fatalf("encrypt[%d]: %v", i, err)
		}
		prng, _ := sampling.NewPRNG()
		p, err := share.Partial(ct, params, 1, prng)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		got, err := Combine(ct, []*Partial{p}, params)
		if err != nil {
			t.Fatalf("combine[%d]: %v", i, err)
		}
		if got != value {
			disagreements++
		}
	}
	if disagreements == 0 {
		t.Fatalf("below-threshold (1 of 3) must not reliably decrypt; got 0/%d disagreements", trials)
	}
}

// Behavioural checks on the sharing.

// TestSharing proves the shares form a genuine t-of-n
// Shamir sharing of a well-defined secret that NO single party holds:
//   - two disjoint-enough t-subsets reconstruct the SAME secret (a consistent
//     sharing of one secret exists), and
//   - no individual party's share equals that secret.
//
// The reconstruction oracle lives ONLY in this test file; production never
// reconstructs s (see TestGate).
func TestSharing(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	_, shares, err := Keygen(params, 2, 3, crsSeed)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	q := params.QLWE()

	// Two quorums must agree, so the shares are a consistent sharing.
	sA := interpolate(t, []Share{shares[0], shares[1]}, q)
	sB := interpolate(t, []Share{shares[1], shares[2]}, q)
	if !equal(sA, sB) {
		t.Fatalf("two t-subsets reconstruct different secrets: shares are not a consistent sharing")
	}

	// No single share equals the secret.
	for _, share := range shares {
		if equal(share.Coeffs, sA) {
			t.Fatalf("share %d equals the reconstructed secret", share.Index)
		}
	}

	// One share alone is not the secret.
	alone := interpolate(t, []Share{shares[0]}, q)
	if equal(alone, sA) {
		t.Fatalf("a single share determines the collective secret")
	}

	// The reconstructed secret is non-trivial.
	allZero := true
	for _, c := range sA {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("reconstructed secret is all-zero")
	}
}

// TestReference checks the reference polynomial follows the seed alone.
func TestReference(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	crp1, _, err := Reference(params, crsSeed)
	if err != nil {
		t.Fatalf("crp1: %v", err)
	}
	crp2, _, err := Reference(params, crsSeed)
	if err != nil {
		t.Fatalf("crp2: %v", err)
	}
	if !crp1.Value.Q.Equal(&crp2.Value.Q) {
		t.Fatalf("reference polynomial is not deterministic for one seed")
	}
	crp3, _, err := Reference(params, []byte("a-different-consensus-seed"))
	if err != nil {
		t.Fatalf("crp3: %v", err)
	}
	if crp1.Value.Q.Equal(&crp3.Value.Q) {
		t.Fatalf("reference polynomial is identical for two seeds")
	}
}

// The protocol messages must carry no whole secret key.

func TestTransport(t *testing.T) {
	forbidden := []string{"SecretKey", "SKLWE", "SKBR"}
	for _, msg := range []interface{}{Public{}, Point{}, Share{}, Partial{}, Member{}, Decryption{}} {
		ty := reflect.TypeOf(msg)
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			fieldStr := f.Name + ":" + f.Type.String()
			for _, bad := range forbidden {
				if strings.Contains(fieldStr, bad) {
					t.Fatalf("wire type %s field %q references forbidden secret material (%q)", ty.Name(), fieldStr, bad)
				}
			}
		}
	}
}

// banned lists calls that would put a whole secret key in one process, plus
// any name denoting reconstruction. GenSecretKeyNew is absent because NewParty
// calls it to sample the member's own contribution.
var banned = map[string]struct{}{
	"GenKeyPair":          {},
	"split":               {},
	"Split":               {},
	"NewDecryptor":        {},
	"NewBitwiseDecryptor": {},
}

var bannedRe = regexp.MustCompile(`(?i)reconstruct|recoversecret|combinesecret|recovermaster`)

// gated is the surface scanned for banned calls.
var gated = map[string]struct{}{
	"Deal":      {},
	"Aggregate": {},
	"Assemble":  {},
	"Keygen":    {},
	"NewParty":  {},
	"partial":   {},
	"Partial":   {},
	"combine":   {},
	"Combine":   {},
	"Decrypt":   {},
	"Encrypt":   {},
}

func TestGate(t *testing.T) {
	// Production source only.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	scanned := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, want := gated[fn.Name.Name]; !want {
				continue
			}
			scanned[fn.Name.Name] = true
			if bad := forbidden(fn.Body); bad != "" {
				t.Errorf("%s calls %q, which would form a whole secret key",
					fn.Name.Name, bad)
			}
		}
	}

	// A rename that drops a function from the gate is itself a failure.
	for name := range gated {
		if !scanned[name] {
			t.Errorf("expected to scan function %q but it was not found (renamed/removed?)", name)
		}
	}
}

// TestTeeth checks the gate flags an injected call.
func TestTeeth(t *testing.T) {
	src := `package x
func victim() {
	sk := genFull()
	split(sk, params, 2, 3)
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "victim" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("synthetic victim not parsed")
	}
	if bad := forbidden(body); bad == "" {
		t.Fatal("negative control: gate failed to flag an injected forbidden call (gate has no teeth)")
	}
}

// forbidden returns the name of the first forbidden call target found in
// body, or "" if clean. Matches both bare calls f(...) and selector calls x.f(...).
func forbidden(body *ast.BlockStmt) string {
	found := ""
	ast.Inspect(body, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if name == "" {
			return true
		}
		if _, bad := banned[name]; bad {
			found = name
			return false
		}
		if bannedRe.MatchString(name) {
			found = name
			return false
		}
		return true
	})
	return found
}

// Test-only reconstruction oracle.

// interpolate recovers the shared secret at x=0 over Z_q. Test-only; the
// structural gate forbids it in production source.
func interpolate(t *testing.T, shares []Share, q uint64) []uint64 {
	t.Helper()
	qBig := new(big.Int).SetUint64(q)
	N := len(shares[0].Coeffs)
	out := make([]uint64, N)
	for i := 0; i < N; i++ {
		acc := new(big.Int)
		for j := range shares {
			xj := big.NewInt(int64(shares[j].Index))
			num := big.NewInt(1)
			den := big.NewInt(1)
			for k := range shares {
				if k == j {
					continue
				}
				xk := big.NewInt(int64(shares[k].Index))
				num.Mul(num, xk)
				num.Mod(num, qBig)
				d := new(big.Int).Sub(xk, xj)
				den.Mul(den, d)
				den.Mod(den, qBig)
			}
			denInv := new(big.Int).ModInverse(den, qBig)
			if denInv == nil {
				t.Fatalf("non-invertible Lagrange denominator (duplicate indices?)")
			}
			lambda := new(big.Int).Mul(num, denInv)
			lambda.Mod(lambda, qBig)
			term := new(big.Int).Mul(lambda, new(big.Int).SetUint64(shares[j].Coeffs[i]))
			acc.Add(acc, term)
			acc.Mod(acc, qBig)
		}
		out[i] = acc.Uint64()
	}
	return out
}

func equal(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
