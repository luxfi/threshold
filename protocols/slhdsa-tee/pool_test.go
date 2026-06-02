// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"

	"github.com/luxfi/mpc/cc/attest"
	"github.com/luxfi/mpc/pkg/kms"
)

// pool_test.go pins the CombinerPool invariants independent of the
// magnetar dispatcher. These tests exercise the freshness gate,
// quorum selection, and divergence-refusal at the slhdsa-tee package
// level so future consumers (mldsa-tee pool, rlwe-tee pool — same
// shape) can mirror the test discipline.

// TestCombinerPool_Constructor_Defaults pins the constructor's
// default-deny posture: Threshold<2, RotationWindow=0, empty
// KnownIssuers all refuse.
func TestCombinerPool_Constructor_Defaults(t *testing.T) {
	cases := []struct {
		name string
		cfg  CombinerPoolConfig
	}{
		{
			name: "threshold-1",
			cfg: CombinerPoolConfig{
				Threshold: 1, RotationWindow: time.Second,
				KnownIssuers: map[string]struct{}{"amd.sev.snp": {}},
			},
		},
		{
			name: "rotation-zero",
			cfg: CombinerPoolConfig{
				Threshold: 2, RotationWindow: 0,
				KnownIssuers: map[string]struct{}{"amd.sev.snp": {}},
			},
		},
		{
			name: "no-issuers",
			cfg: CombinerPoolConfig{
				Threshold: 2, RotationWindow: time.Second,
				KnownIssuers: nil,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewCombinerPool(c.cfg); err == nil {
				t.Fatalf("NewCombinerPool(%s): expected error, got nil", c.name)
			}
		})
	}
}

// TestCombinerPool_AddMember pins per-member registration semantics:
// nil Signer refused, empty name refused, duplicate name refused.
func TestCombinerPool_AddMember(t *testing.T) {
	pool, err := NewCombinerPool(CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: time.Minute,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}

	// nil signer
	if _, err := pool.AddMember("a", nil); err == nil {
		t.Fatal("AddMember nil signer: expected error")
	}

	// empty name
	if _, err := pool.AddMember("", &Signer{}); err == nil {
		t.Fatal("AddMember empty name: expected error")
	}

	// duplicate
	if _, err := pool.AddMember("a", &Signer{}); err != nil {
		t.Fatalf("AddMember a: %v", err)
	}
	if _, err := pool.AddMember("a", &Signer{}); err == nil {
		t.Fatal("AddMember dup a: expected error")
	}

	if pool.MemberCount() != 1 {
		t.Fatalf("MemberCount = %d, want 1", pool.MemberCount())
	}
	if pool.Threshold() != 2 {
		t.Fatalf("Threshold = %d, want 2", pool.Threshold())
	}
	if pool.RotationWindow() != time.Minute {
		t.Fatalf("RotationWindow = %s, want 1m", pool.RotationWindow())
	}
}

// poolMakeSigner builds a Signer over the committed Milan SEV-SNP
// fixture sharing the SAME wrapped seed across members.
func poolMakeSigner(t *testing.T, seed []byte) *Signer {
	t.Helper()
	rim := makeRIM(t)
	hw := makeHardware(t)

	gate := poolMakeGate(t, rim, hw)
	hsmP := newTestFileHSM(t)
	if err := hsmP.StoreKey(context.Background(), "master-seed", seed); err != nil {
		t.Fatalf("StoreKey master-seed: %v", err)
	}
	cfg := Config{
		Mode:             magnetar.ModeM192s,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-seed",
		ApprovalRequired: false,
	}
	signer, err := New(gate, hsmP, newTestApprovalProvider(t), cfg)
	if err != nil {
		t.Fatalf("slhdsatee.New: %v", err)
	}
	return signer
}

func poolMakeGate(t *testing.T, rim, hw [32]byte) *kms.LocalReleaseGate {
	t.Helper()
	policy := kms.NewReleasePolicy([][32]byte{rim}, [][32]byte{hw})
	policy.RequireSEVSNP = true
	var rootKey [32]byte
	if _, err := rand.Read(rootKey[:]); err != nil {
		t.Fatalf("rootKey: %v", err)
	}
	gate, err := kms.NewLocalReleaseGate(policy, kms.NewMemoryNonceStore(), rootKey)
	if err != nil {
		t.Fatalf("NewLocalReleaseGate: %v", err)
	}
	gate.SetIssueTTL(5 * time.Second)
	gate.SetReplayWindow(5 * time.Second)
	return gate
}

// poolMakeSharedSeed returns deterministic SeedSize bytes parameterised
// by label so we can construct multiple Signers with the same seed
// (byte-equality across pool members requires identical seeds) or
// different seeds (divergence path).
func poolMakeSharedSeed(label byte) []byte {
	params := magnetar.MustParamsFor(magnetar.ModeM192s)
	seed := make([]byte, params.SeedSize)
	for i := range seed {
		seed[i] = label ^ byte(i)
	}
	return seed
}

// poolMakeEnvelope builds an Envelope binding the committed Milan
// fixture + KDS replay + fixed-clock options, suitable for both
// pool.Attest and per-call sign.
func poolMakeEnvelope(t *testing.T, rim, hw, teePub [32]byte) *Envelope {
	t.Helper()
	return &Envelope{
		Kind:          attest.KindSEVSNP,
		EvidenceBytes: append([]byte(nil), sevSnpAttestationMilan...),
		RIM:           rim,
		Hardware:      hw,
		TEEPub:        teePub,
		VerifyOpts: []attest.Option{
			attest.WithKDSGetter(newKDSReplay()),
			attest.WithNow(fixedNow()),
		},
	}
}

// TestCombinerPool_Attest_VendorPin pins the vendor allowlist: a
// chain-validated report whose Vendor is not in KnownIssuers refuses.
func TestCombinerPool_Attest_VendorPin(t *testing.T) {
	seed := poolMakeSharedSeed(0xF0)
	signer := poolMakeSigner(t, seed)

	pool, err := NewCombinerPool(CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: time.Minute,
		KnownIssuers: map[string]struct{}{
			"never-issuer": {}, // SEV-SNP path will not match
		},
		Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("a", signer); err != nil {
		t.Fatalf("AddMember a: %v", err)
	}

	rim := makeRIM(t)
	hw := makeHardware(t)
	teePub := makeTEEPub(t)
	env := poolMakeEnvelope(t, rim, hw, teePub)

	err = pool.Attest(context.Background(), "a", env)
	if err == nil {
		t.Fatal("Attest with wrong issuer: expected error, got nil")
	}
}

// TestCombinerPool_Combine_FreshnessGate pins the rotation-window
// gate: members never attested are stale; combine refuses.
func TestCombinerPool_Combine_FreshnessGate(t *testing.T) {
	seed := poolMakeSharedSeed(0xF1)
	signer1 := poolMakeSigner(t, seed)
	signer2 := poolMakeSigner(t, seed)

	pool, err := NewCombinerPool(CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: 30 * time.Second,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            fixedNow,
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("a", signer1); err != nil {
		t.Fatalf("AddMember a: %v", err)
	}
	if _, err := pool.AddMember("b", signer2); err != nil {
		t.Fatalf("AddMember b: %v", err)
	}

	rim := makeRIM(t)
	hw := makeHardware(t)
	teePub := makeTEEPub(t)

	if pool.FreshMemberCount() != 0 {
		t.Fatalf("FreshMemberCount pre-attest = %d, want 0", pool.FreshMemberCount())
	}

	envA := poolMakeEnvelope(t, rim, hw, teePub)
	envB := poolMakeEnvelope(t, rim, hw, teePub)

	// Try Combine without any attestation — pool refuses.
	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	_, _, err = pool.Combine(context.Background(),
		map[string]*Envelope{"a": envA, "b": envB},
		jobID, []byte("freshness"), nil)
	if err == nil {
		t.Fatal("Combine with no attestation: expected error, got nil")
	}
	if !errors.Is(err, ErrMagnetarStaleAttestation) {
		t.Fatalf("Combine pre-attest: expected ErrMagnetarStaleAttestation, got %v", err)
	}
}

// TestCombinerPool_Combine_ByteEqualityAcrossQuorum drives a 2-of-2
// quorum end-to-end and asserts byte-equality across the agreed
// signature. Independent of dispatcher.
func TestCombinerPool_Combine_ByteEqualityAcrossQuorum(t *testing.T) {
	seed := poolMakeSharedSeed(0xF2)
	signer1 := poolMakeSigner(t, seed)
	signer2 := poolMakeSigner(t, seed)

	pool, err := NewCombinerPool(CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: time.Minute,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            fixedNow,
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("a", signer1); err != nil {
		t.Fatalf("AddMember a: %v", err)
	}
	if _, err := pool.AddMember("b", signer2); err != nil {
		t.Fatalf("AddMember b: %v", err)
	}

	rim := makeRIM(t)
	hw := makeHardware(t)
	teePub := makeTEEPub(t)

	if err := pool.Attest(context.Background(), "a", poolMakeEnvelope(t, rim, hw, teePub)); err != nil {
		t.Fatalf("Attest a: %v", err)
	}
	if err := pool.Attest(context.Background(), "b", poolMakeEnvelope(t, rim, hw, teePub)); err != nil {
		t.Fatalf("Attest b: %v", err)
	}
	if pool.FreshMemberCount() != 2 {
		t.Fatalf("FreshMemberCount post-attest = %d, want 2", pool.FreshMemberCount())
	}

	envA := poolMakeEnvelope(t, rim, hw, teePub)
	envB := poolMakeEnvelope(t, rim, hw, teePub)

	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	wire, receipts, err := pool.Combine(context.Background(),
		map[string]*Envelope{"a": envA, "b": envB},
		jobID, []byte("byte-equality"), nil)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("Combine returned empty wire")
	}
	if len(receipts) != 2 {
		t.Fatalf("Combine receipts = %d, want 2", len(receipts))
	}
	for i, r := range receipts {
		if r == nil {
			t.Fatalf("receipt[%d] is nil", i)
		}
		if len(r.AuditSignature) == 0 {
			t.Fatalf("receipt[%d] audit is empty", i)
		}
	}
}

// TestCombinerPool_Combine_Divergence pins the byte-equality discipline:
// two signers holding DIFFERENT seeds produce different bytes; pool
// refuses with ErrMagnetarSignatureDivergence.
func TestCombinerPool_Combine_Divergence(t *testing.T) {
	seedA := poolMakeSharedSeed(0xA1)
	seedB := poolMakeSharedSeed(0xB2) // different seed
	signerA := poolMakeSigner(t, seedA)
	signerB := poolMakeSigner(t, seedB)

	pool, err := NewCombinerPool(CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: time.Minute,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            fixedNow,
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("a", signerA); err != nil {
		t.Fatalf("AddMember a: %v", err)
	}
	if _, err := pool.AddMember("b", signerB); err != nil {
		t.Fatalf("AddMember b: %v", err)
	}

	rim := makeRIM(t)
	hw := makeHardware(t)
	teePub := makeTEEPub(t)

	if err := pool.Attest(context.Background(), "a", poolMakeEnvelope(t, rim, hw, teePub)); err != nil {
		t.Fatalf("Attest a: %v", err)
	}
	if err := pool.Attest(context.Background(), "b", poolMakeEnvelope(t, rim, hw, teePub)); err != nil {
		t.Fatalf("Attest b: %v", err)
	}

	envA := poolMakeEnvelope(t, rim, hw, teePub)
	envB := poolMakeEnvelope(t, rim, hw, teePub)

	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	_, _, err = pool.Combine(context.Background(),
		map[string]*Envelope{"a": envA, "b": envB},
		jobID, []byte("divergence-bytes"), nil)
	if !errors.Is(err, ErrMagnetarSignatureDivergence) {
		t.Fatalf("Combine divergence: expected ErrMagnetarSignatureDivergence, got %v", err)
	}
}
