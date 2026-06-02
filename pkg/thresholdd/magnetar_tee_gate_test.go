// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"

	"github.com/luxfi/mpc/pkg/approval"
	"github.com/luxfi/mpc/pkg/hsm"

	slhdsatee "github.com/luxfi/threshold/protocols/slhdsa-tee"
)

// magnetar_tee_gate_test.go exercises the strict-PQ chain profile
// gate added at 2026-06-01 to close the magnetar v1.1 strict-atom
// transient-SHAKE-bytes residual.
//
// The gate enforces:
//  1. Default profile (legacy-compat): Sign / Sign_Ctx work as before;
//     Sign_TEE works when backend is wired; Combine_TEE works when
//     pool is wired.
//  2. Strict-PQ profile: Sign / Sign_Ctx hard-refuse with
//     ErrMagnetarNoTEEAttestation; only Sign_TEE (single-host attested)
//     and Combine_TEE (t-of-n attested pool) produce signatures.
//  3. Pool freshness: combiners outside rotation window are refused
//     with ErrMagnetarStaleAttestation.
//  4. Pool quorum: at least Threshold attested combiners MUST produce
//     byte-identical output; insufficient or divergent → hard refusal.
//
// Fixture sharing: reuses sevSnpAttestationMilanDispatch /
// sevSnpVcekMilanDispatch + dispatchKDSReplay() / dispatchFixedNow()
// from tee_dispatcher_test.go (same package).

// gateMakeSigner constructs a single slhdsatee.Signer ready to drive
// real SEV-SNP attestation against the committed Milan fixture.
//
// Shared across the pool tests: each pool member holds an independently
// provisioned Signer (independent wrapped seed), so the pool-level
// byte-equality check pins that two combiners with the SAME provisioned
// seed produce the SAME signature.
func gateMakeSigner(t *testing.T, seedBytes []byte) (*slhdsatee.Signer, *magnetar.PublicKey, [32]byte, [32]byte) {
	t.Helper()
	rim := realRIM()
	hw := realHardware()
	gate := dispatchMakeGate(t, rim, hw)
	hsmP := dispatchMakeFileHSM(t)
	appr, err := approval.NewProvider("local-dev", nil)
	if err != nil {
		t.Fatalf("local-dev: %v", err)
	}

	// Pre-seed the wrapped master seed so Provision is deterministic
	// across pool members. Members holding the SAME seed produce
	// byte-identical signatures under SLH-DSA SignDeterministic.
	if len(seedBytes) != magnetar.MustParamsFor(magnetar.ModeM192s).SeedSize {
		t.Fatalf("gateMakeSigner: seed length %d != %d", len(seedBytes), magnetar.MustParamsFor(magnetar.ModeM192s).SeedSize)
	}
	if err := hsmP.StoreKey(context.Background(), "master-seed", seedBytes); err != nil {
		t.Fatalf("StoreKey master-seed: %v", err)
	}

	cfg := slhdsatee.Config{
		Mode:             magnetar.ModeM192s,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-seed",
		ApprovalRequired: false,
	}
	signer, err := slhdsatee.New(gate, hsmP, appr, cfg)
	if err != nil {
		t.Fatalf("slhdsatee.New: %v", err)
	}
	// Derive the published group public key from the same seed via
	// signer.PublicKey (HSM-backed) so the test's verification path
	// uses the canonical pk.
	pub, err := signer.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("signer.PublicKey: %v", err)
	}
	return signer, pub, rim, hw
}

// gateMakeSharedSeed returns deterministic seed bytes so multiple pool
// members can be constructed with the same master seed (pool-level
// byte-equality check requires identical seed across members).
func gateMakeSharedSeed(t *testing.T, label byte) []byte {
	t.Helper()
	params := magnetar.MustParamsFor(magnetar.ModeM192s)
	seed := make([]byte, params.SeedSize)
	for i := range seed {
		seed[i] = label ^ byte(i)
	}
	return seed
}

// TestMagnetarCombine_StrictPQProfile_RequiresTEE pins the central
// gate: a dispatcher whose chain profile is strict-PQ MUST refuse the
// permissionless Sign and Sign_Ctx paths with the canonical sentinel,
// regardless of session state.
func TestMagnetarCombine_StrictPQProfile_RequiresTEE(t *testing.T) {
	sch := newMagnetarScheme()

	// Set up a Keygen session first so the gate is the only thing
	// that can refuse — otherwise an unknown-session error would
	// muddle the failure mode.
	kg, err := sch.Keygen(keygenParams{Threshold: 2, Participants: 3})
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	msg := hex.EncodeToString([]byte("strict-pq-gate"))

	// Permissive default profile — Sign succeeds.
	if _, err := sch.Sign(signParams{MessageHex: msg, PubKeyHex: kg.PublicKey}); err != nil {
		t.Fatalf("Sign under default profile: %v", err)
	}

	// Flip to strict-PQ. Now both Sign and Sign_Ctx MUST refuse.
	sch.SetChainSecurityProfile(slhdsatee.ProfileStrictPQ)

	_, err = sch.Sign(signParams{MessageHex: msg, PubKeyHex: kg.PublicKey})
	if !errors.Is(err, slhdsatee.ErrMagnetarNoTEEAttestation) {
		t.Fatalf("Sign under strict-PQ: expected ErrMagnetarNoTEEAttestation, got %v", err)
	}
	_, err = sch.Sign_Ctx(signCtxParams{MessageHex: msg, PubKeyHex: kg.PublicKey, CtxHex: hex.EncodeToString([]byte("lux-evm-precompile-slhdsa-v1"))})
	if !errors.Is(err, slhdsatee.ErrMagnetarNoTEEAttestation) {
		t.Fatalf("Sign_Ctx under strict-PQ: expected ErrMagnetarNoTEEAttestation, got %v", err)
	}

	// Combine_TEE without wired pool: errMagnetarPoolUnwired.
	_, _, err = sch.Combine_TEE(context.Background(), nil, nil, [32]byte{}, []byte("x"), nil)
	if !errors.Is(err, errMagnetarPoolUnwired) {
		t.Fatalf("Combine_TEE unwired: expected errMagnetarPoolUnwired, got %v", err)
	}

	// Flip back: Sign works again. Demonstrates profile is idempotent
	// + reversible (consensus rotation can flip back if needed).
	sch.SetChainSecurityProfile(slhdsatee.ProfileLegacyCompat)
	if _, err := sch.Sign(signParams{MessageHex: msg, PubKeyHex: kg.PublicKey}); err != nil {
		t.Fatalf("Sign after profile reset: %v", err)
	}
}

// TestMagnetarCombine_AttestationVerified_AllowsSign drives the full
// strict-PQ Combine_TEE path end-to-end against the committed AMD
// Milan SEV-SNP fixture. Asserts:
//   - pool with t-of-n (2-of-3) members + fresh attestations succeeds
//   - output verifies under magnetar.VerifyBytes against the canonical
//     group public key (no caller awareness of the pool's existence)
//   - per-member audit signatures are non-empty
func TestMagnetarCombine_AttestationVerified_AllowsSign(t *testing.T) {
	sharedSeed := gateMakeSharedSeed(t, 0xA1)

	signer1, pub, rim, hw := gateMakeSigner(t, sharedSeed)
	signer2, _, _, _ := gateMakeSigner(t, sharedSeed)
	signer3, _, _, _ := gateMakeSigner(t, sharedSeed)

	now := dispatchFixedNow()
	pool, err := slhdsatee.NewCombinerPool(slhdsatee.CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: 60 * time.Second,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("us-east-1a", signer1); err != nil {
		t.Fatalf("AddMember 1a: %v", err)
	}
	if _, err := pool.AddMember("us-east-1b", signer2); err != nil {
		t.Fatalf("AddMember 1b: %v", err)
	}
	if _, err := pool.AddMember("us-east-1c", signer3); err != nil {
		t.Fatalf("AddMember 1c: %v", err)
	}

	sch := newMagnetarScheme()
	sch.SetChainSecurityProfile(slhdsatee.ProfileStrictPQ)
	sch.SetCombinerPool(pool)

	verifyOpts := []TEEVerifyOption{
		WithKDSGetter(dispatchKDSReplay()),
		WithNow(now),
	}

	// Attest all three combiner members.
	for _, name := range []string{"us-east-1a", "us-east-1b", "us-east-1c"} {
		if err := sch.AttestCombinerMember(context.Background(), name, "sev_snp",
			sevSnpAttestationMilanDispatch, rim, hw, [32]byte{0x11}, verifyOpts); err != nil {
			t.Fatalf("AttestCombinerMember %s: %v", name, err)
		}
	}
	if pool.FreshMemberCount() != 3 {
		t.Fatalf("FreshMemberCount = %d, want 3", pool.FreshMemberCount())
	}

	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	msg := []byte("strict-pq-combine-verified")

	members := []PoolCombineMember{
		{Name: "us-east-1a", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x21}},
		{Name: "us-east-1b", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x22}},
		{Name: "us-east-1c", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x23}},
	}

	wire, audits, err := sch.Combine_TEE(context.Background(), members, verifyOpts, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Combine_TEE: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("Combine_TEE returned empty wire")
	}
	if len(audits) < 2 {
		t.Fatalf("Combine_TEE returned %d audits, want >= 2", len(audits))
	}
	for i, a := range audits {
		if len(a) == 0 {
			t.Fatalf("Combine_TEE audit[%d] is empty", i)
		}
	}

	// External verify path — no awareness of the pool's existence.
	gkBytes, err := magnetar.MarshalGroupKey(pub)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	if !magnetar.VerifyBytes(gkBytes, msg, wire) {
		t.Fatal("Combine_TEE output failed external VerifyBytes")
	}
}

// TestMagnetarCombine_StaleAttestation_RejectsSign pins the freshness
// gate: a pool member whose last attestation lies outside the rotation
// window MUST NOT be selected, and the overall Combine_TEE MUST
// refuse with ErrMagnetarStaleAttestation when insufficient fresh
// members exist.
func TestMagnetarCombine_StaleAttestation_RejectsSign(t *testing.T) {
	sharedSeed := gateMakeSharedSeed(t, 0xB2)

	signer1, _, rim, hw := gateMakeSigner(t, sharedSeed)
	signer2, _, _, _ := gateMakeSigner(t, sharedSeed)
	signer3, _, _, _ := gateMakeSigner(t, sharedSeed)

	// Use a mutable clock so we can advance time to age the
	// freshness state.
	clock := &mutableClock{now: dispatchFixedNow()}
	pool, err := slhdsatee.NewCombinerPool(slhdsatee.CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: 30 * time.Second,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            clock.Now,
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("us-east-1a", signer1); err != nil {
		t.Fatalf("AddMember 1a: %v", err)
	}
	if _, err := pool.AddMember("us-east-1b", signer2); err != nil {
		t.Fatalf("AddMember 1b: %v", err)
	}
	if _, err := pool.AddMember("us-east-1c", signer3); err != nil {
		t.Fatalf("AddMember 1c: %v", err)
	}

	sch := newMagnetarScheme()
	sch.SetChainSecurityProfile(slhdsatee.ProfileStrictPQ)
	sch.SetCombinerPool(pool)

	verifyOpts := []TEEVerifyOption{
		WithKDSGetter(dispatchKDSReplay()),
		WithNow(dispatchFixedNow()), // pin to fixture window
	}

	// Attest all three at clock=now0.
	for _, name := range []string{"us-east-1a", "us-east-1b", "us-east-1c"} {
		if err := sch.AttestCombinerMember(context.Background(), name, "sev_snp",
			sevSnpAttestationMilanDispatch, rim, hw, [32]byte{0x11}, verifyOpts); err != nil {
			t.Fatalf("AttestCombinerMember %s: %v", name, err)
		}
	}

	// Advance the clock past the rotation window. All three members
	// are now stale; pool MUST refuse.
	clock.Advance(45 * time.Second)
	if pool.FreshMemberCount() != 0 {
		t.Fatalf("FreshMemberCount = %d after rotation, want 0", pool.FreshMemberCount())
	}

	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	msg := []byte("strict-pq-stale-rejected")

	members := []PoolCombineMember{
		{Name: "us-east-1a", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x21}},
		{Name: "us-east-1b", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x22}},
		{Name: "us-east-1c", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x23}},
	}

	_, _, err = sch.Combine_TEE(context.Background(), members, verifyOpts, jobID, msg, nil)
	if !errors.Is(err, slhdsatee.ErrMagnetarStaleAttestation) {
		t.Fatalf("Combine_TEE on stale pool: expected ErrMagnetarStaleAttestation, got %v", err)
	}

	// Re-attest two of the three members — that suffices for t=2 to
	// produce a signature. Demonstrates partial-rotation recovery.
	if err := sch.AttestCombinerMember(context.Background(), "us-east-1a", "sev_snp",
		sevSnpAttestationMilanDispatch, rim, hw, [32]byte{0x11}, verifyOpts); err != nil {
		t.Fatalf("Re-attest 1a: %v", err)
	}
	if err := sch.AttestCombinerMember(context.Background(), "us-east-1b", "sev_snp",
		sevSnpAttestationMilanDispatch, rim, hw, [32]byte{0x11}, verifyOpts); err != nil {
		t.Fatalf("Re-attest 1b: %v", err)
	}
	if pool.FreshMemberCount() != 2 {
		t.Fatalf("FreshMemberCount post-rotation = %d, want 2", pool.FreshMemberCount())
	}

	// Now Combine_TEE succeeds with two fresh members (third stale).
	wire, _, err := sch.Combine_TEE(context.Background(), members, verifyOpts, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Combine_TEE after partial rotation: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("Combine_TEE wire empty after partial rotation")
	}
}

// TestMagnetarCombine_TwoOfThreeAttestedCombiners_MatchSig pins the
// quorum robustness: a pool with 3 members but only 2 fresh attestations
// MUST surface a signature when (a) the 2 fresh members agree
// byte-for-byte and (b) the third stale member is not in the selected
// quorum.
func TestMagnetarCombine_TwoOfThreeAttestedCombiners_MatchSig(t *testing.T) {
	sharedSeed := gateMakeSharedSeed(t, 0xC3)

	signer1, pub, rim, hw := gateMakeSigner(t, sharedSeed)
	signer2, _, _, _ := gateMakeSigner(t, sharedSeed)
	signer3, _, _, _ := gateMakeSigner(t, sharedSeed)

	now := dispatchFixedNow()
	pool, err := slhdsatee.NewCombinerPool(slhdsatee.CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: 60 * time.Second,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("us-east-1a", signer1); err != nil {
		t.Fatalf("AddMember 1a: %v", err)
	}
	if _, err := pool.AddMember("us-east-1b", signer2); err != nil {
		t.Fatalf("AddMember 1b: %v", err)
	}
	if _, err := pool.AddMember("us-east-1c", signer3); err != nil {
		t.Fatalf("AddMember 1c: %v", err)
	}

	sch := newMagnetarScheme()
	sch.SetChainSecurityProfile(slhdsatee.ProfileStrictPQ)
	sch.SetCombinerPool(pool)

	verifyOpts := []TEEVerifyOption{
		WithKDSGetter(dispatchKDSReplay()),
		WithNow(now),
	}

	// Attest only 1a + 1b. 1c stays un-attested.
	for _, name := range []string{"us-east-1a", "us-east-1b"} {
		if err := sch.AttestCombinerMember(context.Background(), name, "sev_snp",
			sevSnpAttestationMilanDispatch, rim, hw, [32]byte{0x11}, verifyOpts); err != nil {
			t.Fatalf("AttestCombinerMember %s: %v", name, err)
		}
	}
	if pool.FreshMemberCount() != 2 {
		t.Fatalf("FreshMemberCount = %d, want 2", pool.FreshMemberCount())
	}

	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	msg := []byte("strict-pq-2-of-3-attested-match")

	members := []PoolCombineMember{
		{Name: "us-east-1a", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x21}},
		{Name: "us-east-1b", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x22}},
		{Name: "us-east-1c", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x23}},
	}

	wire, audits, err := sch.Combine_TEE(context.Background(), members, verifyOpts, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Combine_TEE 2-of-3 attested: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("audits count = %d, want 2 (only 1a + 1b attested)", len(audits))
	}

	// Verifies under the canonical pub.
	gkBytes, err := magnetar.MarshalGroupKey(pub)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	if !magnetar.VerifyBytes(gkBytes, msg, wire) {
		t.Fatal("Combine_TEE 2-of-3 output failed external VerifyBytes")
	}

	// Drop the threshold further by un-attesting 1b. Now only 1a is
	// fresh; quorum=2 must refuse.
	clock2 := &mutableClock{now: now}
	pool2, _ := slhdsatee.NewCombinerPool(slhdsatee.CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: 60 * time.Second,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            clock2.Now,
	})
	if _, err := pool2.AddMember("us-east-1a", signer1); err != nil {
		t.Fatalf("AddMember 1a (pool2): %v", err)
	}
	if _, err := pool2.AddMember("us-east-1b", signer2); err != nil {
		t.Fatalf("AddMember 1b (pool2): %v", err)
	}
	if _, err := pool2.AddMember("us-east-1c", signer3); err != nil {
		t.Fatalf("AddMember 1c (pool2): %v", err)
	}
	sch2 := newMagnetarScheme()
	sch2.SetChainSecurityProfile(slhdsatee.ProfileStrictPQ)
	sch2.SetCombinerPool(pool2)
	if err := sch2.AttestCombinerMember(context.Background(), "us-east-1a", "sev_snp",
		sevSnpAttestationMilanDispatch, rim, hw, [32]byte{0x11}, verifyOpts); err != nil {
		t.Fatalf("AttestCombinerMember pool2 1a: %v", err)
	}
	// With 1-of-3 attested and 2-of-3 NEVER attested, the pool surfaces
	// the freshness-class refusal (stale) because un-attested members
	// have LastIssuedAt == zero, which the pool treats as outside any
	// rotation window. Stale wins over insufficient when ANY would-be
	// quorum member's freshness has lapsed (or never started). Both
	// sentinels would have been acceptable; we pin the actual surface.
	_, _, err = sch2.Combine_TEE(context.Background(), members, verifyOpts, jobID, msg, nil)
	if !errors.Is(err, slhdsatee.ErrMagnetarStaleAttestation) && !errors.Is(err, slhdsatee.ErrMagnetarInsufficientQuorum) {
		t.Fatalf("Combine_TEE 1-of-3 attested: expected stale or insufficient-quorum sentinel, got %v", err)
	}
}

// TestMagnetarCombine_SignatureDivergence_HardRefusal pins the
// byte-equality discipline: if two attested combiners disagree on the
// produced bytes (corruption or compromise), the pool MUST refuse with
// ErrMagnetarSignatureDivergence — no silent winner-picking.
//
// We exercise this by registering two members with DIFFERENT seeds —
// SLH-DSA SignDeterministic over different seeds produces different
// bytes, which the pool's byte-equality compare must reject.
func TestMagnetarCombine_SignatureDivergence_HardRefusal(t *testing.T) {
	seedA := gateMakeSharedSeed(t, 0xD4)
	seedB := gateMakeSharedSeed(t, 0xE5)

	signer1, _, rim, hw := gateMakeSigner(t, seedA)
	signer2, _, _, _ := gateMakeSigner(t, seedB) // DIFFERENT seed
	signer3, _, _, _ := gateMakeSigner(t, seedA)

	now := dispatchFixedNow()
	pool, err := slhdsatee.NewCombinerPool(slhdsatee.CombinerPoolConfig{
		Threshold:      2,
		RotationWindow: 60 * time.Second,
		KnownIssuers:   map[string]struct{}{"amd.sev.snp": {}},
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewCombinerPool: %v", err)
	}
	if _, err := pool.AddMember("alpha", signer1); err != nil {
		t.Fatalf("AddMember alpha: %v", err)
	}
	if _, err := pool.AddMember("beta", signer2); err != nil {
		t.Fatalf("AddMember beta: %v", err)
	}
	if _, err := pool.AddMember("gamma", signer3); err != nil {
		t.Fatalf("AddMember gamma: %v", err)
	}

	sch := newMagnetarScheme()
	sch.SetChainSecurityProfile(slhdsatee.ProfileStrictPQ)
	sch.SetCombinerPool(pool)

	verifyOpts := []TEEVerifyOption{
		WithKDSGetter(dispatchKDSReplay()),
		WithNow(now),
	}

	// Attest alpha + beta only — Threshold=2, first 2 in name order
	// will be selected for the quorum. They hold different seeds, so
	// their wire output diverges.
	for _, name := range []string{"alpha", "beta"} {
		if err := sch.AttestCombinerMember(context.Background(), name, "sev_snp",
			sevSnpAttestationMilanDispatch, rim, hw, [32]byte{0x11}, verifyOpts); err != nil {
			t.Fatalf("AttestCombinerMember %s: %v", name, err)
		}
	}

	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	msg := []byte("divergence-refused")

	members := []PoolCombineMember{
		{Name: "alpha", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x21}},
		{Name: "beta", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x22}},
		{Name: "gamma", Kind: "sev_snp", EvidenceBytes: sevSnpAttestationMilanDispatch, RIM: rim, Hardware: hw, TEEPub: [32]byte{0x23}},
	}

	_, _, err = sch.Combine_TEE(context.Background(), members, verifyOpts, jobID, msg, nil)
	if !errors.Is(err, slhdsatee.ErrMagnetarSignatureDivergence) {
		t.Fatalf("Combine_TEE on divergent quorum: expected ErrMagnetarSignatureDivergence, got %v", err)
	}
}

// mutableClock is a manually-advanced wall-clock used to age the
// pool's freshness state.
type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time { return c.now }

func (c *mutableClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// dispatchMakeFileHSM_consolidated is referenced by the older
// dispatcher tests via dispatchMakeFileHSM; included here for the
// hsm.Provider import alias to satisfy the new test file's references.
var _ hsm.Provider = (hsm.Provider)(nil)
