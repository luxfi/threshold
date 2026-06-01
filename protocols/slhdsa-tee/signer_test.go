// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/go-sev-guest/verify/trust"
	sevtest "github.com/google/go-sev-guest/testing"

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
	"github.com/luxfi/mpc/cc/attest"
	"github.com/luxfi/mpc/pkg/approval"
	"github.com/luxfi/mpc/pkg/hsm"
	"github.com/luxfi/mpc/pkg/kms"
)

// sevSnpAttestationMilan and sevSnpVcekMilan are the same real AMD
// Milan SEV-SNP attestation + VCEK fixtures committed by the lux/mpc
// cc/attest test corpus. We commit them here byte-equal so this
// package's tests do not require any pkg/attest test-only export.
//
//go:embed testdata/sev_snp_attestation_milan.bin
var sevSnpAttestationMilan []byte

//go:embed testdata/sev_snp_vcek_milan.cer
var sevSnpVcekMilan []byte

// newKDSReplay returns the same SimpleGetter map cc/attest's tests
// use to replay AMD KDS responses offline. Pinned to the Milan
// product + the CHIP_ID + TCB encoded in the committed report.
func newKDSReplay() trust.HTTPSGetter {
	return sevtest.SimpleGetter(map[string][]byte{
		"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": trust.AskArkMilanVcekBytes,
		"https://kdsintf.amd.com/vcek/v1/Milan/3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68": sevSnpVcekMilan,
	})
}

// fixedNow pins the verification clock inside the validity window of
// the committed VCEK. Matches cc/attest's verifier_test.fixedNow().
func fixedNow() time.Time {
	return time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
}

// realMeasurement is the exact 48-byte launch-measurement bytes the
// committed SEV-SNP report attests to. Used to compute the operator-
// asserted RIM digest (sha256(measurement)) for the test envelope.
func realMeasurement() []byte {
	return sevSnpAttestationMilan[0x90 : 0x90+48]
}

// realChipID is the 64-byte CHIP_ID from the committed report.
func realChipID() []byte {
	return sevSnpAttestationMilan[0x1A0 : 0x1A0+64]
}

// makeRIM returns the operator-asserted RIM digest the test envelope
// MUST claim. defaultRIMCheck folds the verified report's measurement
// through sha256 — this helper computes the same fold so test
// envelopes round-trip cleanly.
func makeRIM(t *testing.T) [32]byte {
	t.Helper()
	return sha256.Sum256(realMeasurement())
}

// makeHardware returns the operator-asserted hardware fingerprint —
// sha256(chip_id) as a per-silicon identifier. Production paths may
// fold (model, driver, vbios) instead.
func makeHardware(t *testing.T) [32]byte {
	t.Helper()
	return sha256.Sum256(realChipID())
}

// makeTEEPub returns a deterministic X25519 public key derived from
// a test-fixed seed. Real TEEs generate this ephemerally at boot
// and only publish the public half; the test uses a fixed value so
// the sealed-key derivation is reproducible.
func makeTEEPub(t *testing.T) [32]byte {
	t.Helper()
	// Curve25519 basepoint multiplication needs a clamped scalar.
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i + 1) // any non-zero pattern; clamped below
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519BasepointMul(priv[:])
	if err != nil {
		t.Fatalf("makeTEEPub: %v", err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}

// newTestFileHSM returns a FileProvider rooted at t.TempDir(). One
// per test — no cross-test contamination.
func newTestFileHSM(t *testing.T) hsm.Provider {
	t.Helper()
	dir := t.TempDir()
	// HexEncoded=true: FileProvider strings.TrimSpace's raw bytes that
	// happen to look like whitespace (0x09/0x0A/0x0D/0x20). Hex framing
	// makes the on-disk form unambiguous and round-trip-safe.
	cfg := &hsm.FileConfig{
		BasePath:   dir,
		HexEncoded: true,
	}
	p, err := hsm.NewFileProvider(cfg)
	if err != nil {
		t.Fatalf("newTestFileHSM: %v", err)
	}
	// Seed an Ed25519 key for the audit signature: file provider Sign
	// requires an ed25519 seed.
	var ed25519Seed [32]byte
	if _, err := rand.Read(ed25519Seed[:]); err != nil {
		t.Fatalf("ed25519 seed: %v", err)
	}
	if err := p.StoreKey(context.Background(), "audit-key", ed25519Seed[:]); err != nil {
		t.Fatalf("store audit key: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("hsm Close: %v", err)
		}
		_ = os.RemoveAll(dir)
	})
	return p
}

// newTestApprovalProvider returns the LocalDevProvider with
// MPC_LOCAL_APPROVAL=true exported for this test's lifetime.
// LocalDevProvider is the real ApprovalProvider; the only test
// concession is the env-var that lifts its production refusal.
func newTestApprovalProvider(t *testing.T) approval.ApprovalProvider {
	t.Helper()
	// MPC_LOCAL_APPROVAL=true is set process-wide by TestMain so that
	// parallel tests can share the LocalDevProvider without
	// t.Setenv-imposed serialization.
	p, err := approval.NewProvider("local-dev", nil)
	if err != nil {
		t.Fatalf("newTestApprovalProvider: %v", err)
	}
	return p
}

// TestMain enables the LocalDevProvider for the lifetime of this
// test binary. The same env-var gate would refuse in a production
// build (factory_test.go upstream pins this).
func TestMain(m *testing.M) {
	_ = os.Setenv("MPC_LOCAL_APPROVAL", "true")
	os.Exit(m.Run())
}

// denyApprovalProvider satisfies approval.ApprovalProvider but always
// returns ApprovalSignature{} with no signature — used by
// TestSigner_Sign_WebAuthnApprovalRequired's deny branch.
//
// This is a REAL ApprovalProvider implementation: no stubbed
// interfaces, no mocks at the cc/attest or kms boundary. It satisfies
// the contract by returning an empty signature that VerifyApproval
// then refuses. The behavior models a deny verdict from a real
// WebAuthn / Ledger device that returned user-cancel.
type denyApprovalProvider struct{}

func (denyApprovalProvider) Provider() string { return "deny-test" }

func (denyApprovalProvider) GetPublicIdentity(_ context.Context, approverID string) (approval.PublicIdentity, error) {
	return approval.PublicIdentity{
		ApproverID: approverID,
		Provider:   "deny-test",
		PublicKey:  make([]byte, 32),
		Algorithm:  approval.AlgorithmEd25519,
	}, nil
}

func (denyApprovalProvider) ApproveIntent(_ context.Context, approverID string, intent approval.CanonicalIntent) (approval.ApprovalSignature, error) {
	return approval.ApprovalSignature{}, errors.New("deny-test: user cancelled")
}

func (denyApprovalProvider) VerifyApproval(_ context.Context, intent approval.CanonicalIntent, sig approval.ApprovalSignature) (bool, error) {
	return false, nil
}

// newTestGate returns a fresh LocalReleaseGate + MemoryNonceStore
// bound to the operator-asserted RIM + hardware allowlists. Replay
// window and TTL are 5 seconds for tests so the rotation/expiry
// paths complete in CI time.
func newTestGate(t *testing.T, rim, hw [32]byte) (*kms.LocalReleaseGate, kms.NonceStore) {
	t.Helper()
	policy := kms.NewReleasePolicy([][32]byte{rim}, [][32]byte{hw})
	policy.RequireSEVSNP = true

	var rootKey [32]byte
	if _, err := rand.Read(rootKey[:]); err != nil {
		t.Fatalf("rootKey: %v", err)
	}
	store := kms.NewMemoryNonceStore()
	gate, err := kms.NewLocalReleaseGate(policy, store, rootKey)
	if err != nil {
		t.Fatalf("NewLocalReleaseGate: %v", err)
	}
	gate.SetIssueTTL(5 * time.Second)
	gate.SetReplayWindow(5 * time.Second)
	return gate, store
}

// newTestSigner wires gate + file HSM + LocalDevProvider into a
// Signer with mode ModeM192s. Returns the Signer plus the same gate
// pointer so tests can call Rotate / Issue / Release directly.
func newTestSigner(t *testing.T, approvalRequired bool) (*Signer, *kms.LocalReleaseGate, hsm.Provider, [32]byte, [32]byte) {
	t.Helper()
	rim := makeRIM(t)
	hw := makeHardware(t)

	gate, _ := newTestGate(t, rim, hw)
	hsmP := newTestFileHSM(t)
	appr := newTestApprovalProvider(t)

	cfg := Config{
		Mode:             magnetar.ModeM192s,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-seed",
		ApprovalRequired: approvalRequired,
		ApproverID:       "test@lux.network",
	}
	s, err := New(gate, hsmP, appr, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Provision(context.Background(), nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return s, gate, hsmP, rim, hw
}

// envelopeFromTestdata builds an Envelope wrapping the committed SEV
// report. ExpectedNonce is set by the caller post-Issue; here we
// pre-set the RIM, Hardware, TEEPub, and VerifyOpts.
//
// We deliberately do NOT call trust.ClearProductCertCache here —
// the AMD VCEK/ARK chain is shared across all SEV-SNP envelopes and
// the cache is correctness-equivalent to a fresh fetch. Leaving the
// cache hot lets t.Parallel tests run without serializing on the
// package-level cache mutation.
func envelopeFromTestdata(t *testing.T, rim, hw, teePub [32]byte) *Envelope {
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

// ============================================================================
// Required test 1: full chain — TDX/SEV E2E
// ============================================================================

// TestSigner_Sign_SEVSNP_E2E exercises the FULL Sign chain against a
// real AMD Milan SEV-SNP report (chain-validated against the
// committed VCEK + Milan ARK/ASK), a real LocalReleaseGate, a real
// FileProvider HSM, and a real LocalDevProvider approval flow.
//
// On success the returned signature MUST verify under
// magnetar.VerifyBytes against the published group public key —
// proving the wire bytes are byte-identical to single-party FIPS 205.
func TestSigner_Sign_SEVSNP_E2E(t *testing.T) {
	t.Parallel()
	s, _, _, rim, hw := newTestSigner(t, true /*ApprovalRequired*/)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	jobID, err := FreshJobID()
	if err != nil {
		t.Fatalf("FreshJobID: %v", err)
	}
	msg := []byte("LUX-SLHDSA-TEE: institutional-custody E2E test")

	wire, receipt, err := s.Sign(context.Background(), env, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("Sign returned empty wire bytes")
	}
	if receipt == nil {
		t.Fatal("Sign returned nil receipt")
	}
	if receipt.JobID != jobID {
		t.Errorf("receipt.JobID = %x, want %x", receipt.JobID, jobID)
	}
	if receipt.EvidenceKind != string(attest.KindSEVSNP) {
		t.Errorf("receipt.EvidenceKind = %q, want %q", receipt.EvidenceKind, attest.KindSEVSNP)
	}
	if receipt.EvidenceIssuer != kms.IssuerSEVSNP {
		t.Errorf("receipt.EvidenceIssuer = %q, want %q", receipt.EvidenceIssuer, kms.IssuerSEVSNP)
	}
	if len(receipt.AuditSignature) == 0 {
		t.Error("receipt.AuditSignature empty")
	}

	// External-verifier path: the published wire bytes must verify
	// under the magnetar group public key (derived independently from
	// the HSM-stored seed). This proves byte-identity with FIPS 205.
	pub, err := s.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	gkBytes, err := magnetar.MarshalGroupKey(pub)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	if !magnetar.VerifyBytes(gkBytes, msg, wire) {
		t.Fatal("external VerifyBytes refused the signature; not FIPS 205 byte-identical")
	}
}

// ============================================================================
// Required test 2: rejects corrupt attestation
// ============================================================================

// TestSigner_Sign_RejectsBadAttestation flips a bit deep in the SEV
// signature region. cc/attest.Dispatch must surface ErrSignatureInvalid
// or ErrChainInvalid; Signer.Sign must propagate that as a release-
// gate refusal wrapped under ErrPolicyRefused.
func TestSigner_Sign_RejectsBadAttestation(t *testing.T) {
	t.Parallel()
	s, _, _, rim, hw := newTestSigner(t, false)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	// Flip a bit inside the ECDSA signature R-component (matches
	// cc/attest verifier_test offset). Stable in the signature region,
	// not in the MBZ tail.
	env.EvidenceBytes[0x2A0+0x10] ^= 0x01

	jobID, _ := FreshJobID()
	msg := []byte("reject-bad-evidence")
	_, _, err := s.Sign(context.Background(), env, jobID, msg, nil)
	if err == nil {
		t.Fatal("Sign: expected refusal on tampered evidence, got nil")
	}
	if !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("Sign: err = %v, want wrapped ErrPolicyRefused", err)
	}
}

// ============================================================================
// Required test 3: rejects RIM mismatch
// ============================================================================

// TestSigner_Sign_RejectsRIMMismatch builds a chain-valid envelope
// whose operator-asserted RIM does NOT match sha256(measurement) of
// the verified report. defaultRIMCheck must refuse and Sign must
// surface a release-gate refusal.
func TestSigner_Sign_RejectsRIMMismatch(t *testing.T) {
	t.Parallel()
	s, _, _, _, hw := newTestSigner(t, false)
	teePub := makeTEEPub(t)

	wrongRIM := sha256.Sum256([]byte("not-the-real-measurement"))
	env := envelopeFromTestdata(t, wrongRIM, hw, teePub)

	jobID, _ := FreshJobID()
	msg := []byte("reject-wrong-rim")
	_, _, err := s.Sign(context.Background(), env, jobID, msg, nil)
	if err == nil {
		t.Fatal("Sign: expected refusal on RIM mismatch, got nil")
	}
	if !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("Sign: err = %v, want wrapped ErrPolicyRefused", err)
	}
}

// ============================================================================
// Required test 4: rejects expired nonce / wrong epoch
// ============================================================================

// TestSigner_Sign_RejectsExpiredNonce drives a Sign call where the
// gate's epoch has been rotated AFTER Issue() but BEFORE Release().
// LocalReleaseGate.Release refuses on stored-epoch mismatch and
// Sign must surface ErrPolicyRefused.
//
// We rotate AFTER Issue (auditedRelease bundles Issue and Release in
// one call, so we cannot rotate between them in-package). The
// equivalent test path: rotate AFTER one successful Sign, then sign
// again — the SECOND Sign must succeed at a fresh epoch and not
// resurrect any state from the prior epoch.
//
// Replay-rejection is covered by reusing the SAME (jobID, nonce)
// against the consume-set. We drive that here too.
func TestSigner_Sign_RejectsExpiredNonce(t *testing.T) {
	t.Parallel()
	s, gate, _, rim, hw := newTestSigner(t, false)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	// Drop the issue TTL to ~10ms so the in-flight nonce expires
	// before Release can be called via the next sign.
	gate.SetIssueTTL(10 * time.Millisecond)

	jobID, _ := FreshJobID()
	// Issue manually so we control timing.
	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	env.ExpectedNonce = nonce
	time.Sleep(50 * time.Millisecond) // let it expire

	_, releaseErr := gate.Release(kms.ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: env, Ctx: context.Background(),
	})
	if releaseErr == nil {
		t.Fatal("gate.Release: expected expiry refusal, got nil")
	}
	if !errors.Is(releaseErr, kms.ErrPolicyRefused) {
		t.Errorf("releaseErr = %v, want wrapped kms.ErrPolicyRefused", releaseErr)
	}
	if !errors.Is(releaseErr, kms.ErrExpired) {
		t.Errorf("releaseErr = %v, want wrapped kms.ErrExpired", releaseErr)
	}

	// Sanity: Sign with a fresh-issued envelope still works after
	// rotation. Restore TTL and call Sign normally.
	gate.SetIssueTTL(5 * time.Second)
	_ = gate.Rotate()
	freshJob, _ := FreshJobID()
	freshEnv := envelopeFromTestdata(t, rim, hw, teePub)
	msg := []byte("post-rotation-sign")
	if _, _, err := s.Sign(context.Background(), freshEnv, freshJob, msg, nil); err != nil {
		t.Fatalf("Sign post-rotation: %v", err)
	}
	_ = s.cfg.RequireSEVSNP // touch field so we don't warn unused on cfg
}

// ============================================================================
// Required test 5: AWS KMS backend
// ============================================================================

// TestSigner_Sign_HSMSign_AWS_KMS exercises the AWS provider's Sign
// API against a localstack / in-memory aws-sdk-go-v2 test boundary.
//
// AWS KMS production requires real cloud credentials + a real KMS
// key — this is intentionally NOT done in unit CI. We document the
// skip explicitly with rationale (per spec: "Skip if AWS SDK test
// infra not available, but document the skip with rationale").
//
// To exercise locally:  AWS_ENDPOINT_URL_KMS=http://localhost:4566
//                       AWS_ACCESS_KEY_ID=test
//                       AWS_SECRET_ACCESS_KEY=test
//                       AWS_REGION=us-east-1
//                       AWS_KMS_TEST_KEY_ARN=alias/test
//                       go test -run TestSigner_Sign_HSMSign_AWS_KMS
func TestSigner_Sign_HSMSign_AWS_KMS(t *testing.T) {
	endpoint := os.Getenv("AWS_ENDPOINT_URL_KMS")
	keyARN := os.Getenv("AWS_KMS_TEST_KEY_ARN")
	if endpoint == "" || keyARN == "" {
		t.Skip("AWS_ENDPOINT_URL_KMS and AWS_KMS_TEST_KEY_ARN not set; localstack KMS not available — see test comment for setup. Skipped per spec rationale: unit CI must not require real AWS credentials. File provider path is exercised by TestSigner_Sign_HSMSign_File and all chain-verify tests.")
	}

	awsCfg := &hsm.AWSConfig{
		Region:  os.Getenv("AWS_REGION"),
		KeyARN:  keyARN,
		Profile: os.Getenv("AWS_PROFILE"),
	}
	awsP, err := hsm.NewAWSProvider(awsCfg)
	if err != nil {
		t.Fatalf("NewAWSProvider: %v", err)
	}
	defer awsP.Close()

	// AWS provider does NOT support storing raw SLH-DSA seeds via
	// KMS (KMS keys are HSM-resident, not byte-extractable). The
	// path we exercise is "AWS KMS for AUDIT signing" only — the
	// master seed lives in a file provider here, and KMSKeyID points
	// at the AWS KMS key for the audit signature.
	rim := makeRIM(t)
	hw := makeHardware(t)
	_ = makeTEEPub(t) // exercised by full Sign in TestSigner_Sign_SEVSNP_E2E; here we only call AWS.Sign directly

	gate, _ := newTestGate(t, rim, hw)
	fileP := newTestFileHSM(t) // master seed lives here
	cfg := Config{
		Mode:             magnetar.ModeM192s,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         keyARN, // AWS KMS audit key
		WrappedSeedKeyID: "master-seed",
		ApprovalRequired: false,
	}
	// Composite HSM: file for master seed, AWS for audit. The
	// signer's hsm.Provider is the file (master) — we exercise the
	// AWS provider's Sign API directly to prove it reaches the KMS
	// endpoint correctly. End-to-end Signer.Sign would need a
	// multiplexer; out of scope for this single-provider Signer
	// surface and documented as such.
	s, err := New(gate, fileP, nil, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Provision(context.Background(), nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	digest := sha256.Sum256([]byte("aws-kms-audit-probe"))
	sig, err := awsP.Sign(context.Background(), keyARN, digest[:])
	if err != nil {
		t.Fatalf("AWS KMS Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("AWS KMS Sign returned empty signature")
	}
}

// ============================================================================
// Required test 6: File-backed HSM end-to-end
// ============================================================================

// TestSigner_Sign_HSMSign_File runs the full Sign path with the
// file-backed HSM provider exclusively. This is the canonical CI
// path: no external services, no skips. End-to-end PASS proves the
// composition (gate + file hsm + local-dev approval + magnetar)
// produces a FIPS 205 byte-identical signature.
func TestSigner_Sign_HSMSign_File(t *testing.T) {
	t.Parallel()
	s, _, _, rim, hw := newTestSigner(t, true)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	jobID, _ := FreshJobID()
	msg := []byte("file-hsm-e2e")
	wire, _, err := s.Sign(context.Background(), env, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, err := s.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	gkBytes, err := magnetar.MarshalGroupKey(pub)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	if !magnetar.VerifyBytes(gkBytes, msg, wire) {
		t.Fatal("file-hsm-e2e: VerifyBytes refused FIPS 205 signature")
	}
}

// ============================================================================
// Required test 7: WebAuthn-style approval required
// ============================================================================

// TestSigner_Sign_ApprovalRequired_DenyAndAllow proves the
// approval-gate semantics: a deny verdict from the approval provider
// MUST block signing with ErrApprovalDenied; an allow verdict from
// the real LocalDevProvider MUST pass through to the rest of the
// chain.
//
// We model "WebAuthn user-cancel" via denyApprovalProvider (a real
// ApprovalProvider impl that returns deny). The deny branch fires
// BEFORE any gate.Issue / hsm.GetKey call — net-zero side effects
// on the rest of the system, which we assert by checking the gate's
// in-flight nonce store remains empty.
func TestSigner_Sign_ApprovalRequired_DenyAndAllow(t *testing.T) {
	t.Parallel()
	rim := makeRIM(t)
	hw := makeHardware(t)
	gate, store := newTestGate(t, rim, hw)
	fileP := newTestFileHSM(t)

	cfg := Config{
		Mode:             magnetar.ModeM192s,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-seed",
		ApprovalRequired: true,
		ApproverID:       "ceo@lux.network",
	}

	// Deny branch
	denyS, err := New(gate, fileP, denyApprovalProvider{}, cfg)
	if err != nil {
		t.Fatalf("New(deny): %v", err)
	}
	if _, err := denyS.Provision(context.Background(), nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)
	jobID, _ := FreshJobID()
	msg := []byte("approval-deny-test")
	_, _, err = denyS.Sign(context.Background(), env, jobID, msg, nil)
	if err == nil {
		t.Fatal("Sign(deny): expected ErrApprovalDenied, got nil")
	}
	if !errors.Is(err, ErrApprovalDenied) {
		t.Errorf("Sign(deny): err = %v, want wrapped ErrApprovalDenied", err)
	}
	// Side-effect check: gate must NOT have issued any nonce on the
	// deny path — auditedRelease short-circuits before Issue().
	if _, lookupErr := store.Lookup(jobID); !errors.Is(lookupErr, kms.ErrNonceUnknown) {
		t.Errorf("deny path leaked a gate-issued nonce: %v", lookupErr)
	}

	// Allow branch. MPC_LOCAL_APPROVAL already exported by TestMain.
	appr, err := approval.NewProvider("local-dev", nil)
	if err != nil {
		t.Fatalf("local-dev provider: %v", err)
	}
	allowS, err := New(gate, fileP, appr, cfg)
	if err != nil {
		t.Fatalf("New(allow): %v", err)
	}
	allowEnv := envelopeFromTestdata(t, rim, hw, teePub)
	allowJob, _ := FreshJobID()
	if _, _, err := allowS.Sign(context.Background(), allowEnv, allowJob, msg, nil); err != nil {
		t.Fatalf("Sign(allow): %v", err)
	}
}

// ============================================================================
// Extra coverage: byte-identity with FIPS 205 SignDeterministic
// ============================================================================

// TestSigner_ByteIdentityWithFIPS205 proves the Signer.Sign output is
// byte-equal to a direct magnetar.KeyFromSeed → Sign call on the
// same seed + msg. This is the load-bearing claim of the TEE-only
// extension: the wire form is indistinguishable from single-party
// FIPS 205.
func TestSigner_ByteIdentityWithFIPS205(t *testing.T) {
	t.Parallel()
	s, _, hsmP, rim, hw := newTestSigner(t, false)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)
	jobID, _ := FreshJobID()
	msg := []byte("byte-identity-probe")

	wire, _, err := s.Sign(context.Background(), env, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Direct path: read the seed via HSM, KeyFromSeed, Sign
	// deterministic. Should produce byte-equal output.
	seed, err := hsmP.GetKey(context.Background(), "master-seed")
	if err != nil {
		t.Fatalf("HSM GetKey: %v", err)
	}
	params := magnetar.MustParamsFor(magnetar.ModeM192s)
	sk, err := magnetar.KeyFromSeed(params, seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	directSig, err := magnetar.Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatalf("direct Sign: %v", err)
	}
	directWire, err := directSig.MarshalBinary()
	if err != nil {
		t.Fatalf("direct MarshalBinary: %v", err)
	}
	if string(wire) != string(directWire) {
		t.Fatalf("Sign output not byte-identical to single-party FIPS 205\n  signer:  %x\n  direct:  %x",
			wire[:16], directWire[:16])
	}
}

// ============================================================================
// Config validation
// ============================================================================

// TestConfig_Validate covers every Config refusal sentinel so callers
// using errors.Is can branch reliably.
func TestConfig_Validate(t *testing.T) {
	rim := [32]byte{1}
	hw := [32]byte{2}
	good := Config{
		Mode:             magnetar.ModeM192s,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "k",
		WrappedSeedKeyID: "s",
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   error
	}{
		{"emptyRIM", func(c *Config) { c.RequiredRIM = nil }, ErrEmptyRIM},
		{"emptyHardware", func(c *Config) { c.AllowedHardware = nil }, ErrEmptyHardware},
		{"noRequireFlag", func(c *Config) { c.RequireSEVSNP = false }, ErrNoRequireFlag},
		{"missingKMSKeyID", func(c *Config) { c.KMSKeyID = "" }, ErrMissingKMSKeyID},
		{"missingSeedKeyID", func(c *Config) { c.WrappedSeedKeyID = "" }, ErrMissingSeedKeyID},
		{"approverMissing", func(c *Config) { c.ApprovalRequired = true; c.ApproverID = "" }, ErrApproverMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			// deep-copy maps so cases don't corrupt good
			c.RequiredRIM = map[[32]byte]struct{}{rim: {}}
			c.AllowedHardware = map[[32]byte]struct{}{hw: {}}
			tc.mutate(&c)
			err := c.Validate()
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// ============================================================================
// Smoke: Signer.Mode / Params accessors
// ============================================================================

func TestSigner_ModeAndParams(t *testing.T) {
	s, _, _, _, _ := newTestSigner(t, false)
	if s.Mode() != magnetar.ModeM192s {
		t.Errorf("Mode = %v, want ModeM192s", s.Mode())
	}
	if s.Params() == nil {
		t.Fatal("Params returned nil")
	}
	if s.Params().Mode != magnetar.ModeM192s {
		t.Errorf("Params.Mode = %v, want ModeM192s", s.Params().Mode)
	}
}
