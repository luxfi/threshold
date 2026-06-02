// SPDX-License-Identifier: BSD-3-Clause

package rlwetee

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"errors"
	"os"
	"testing"
	"time"

	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"

	coronaThreshold "github.com/luxfi/corona/threshold"

	"github.com/luxfi/mpc/cc/attest"
	"github.com/luxfi/mpc/pkg/approval"
	"github.com/luxfi/mpc/pkg/hsm"
	"github.com/luxfi/mpc/pkg/kms"
)

// Real AMD Milan SEV-SNP attestation fixtures (same bytes as the
// lux/mpc cc/attest test corpus).
//
//go:embed testdata/sev_snp_attestation_milan.bin
var sevSnpAttestationMilan []byte

//go:embed testdata/sev_snp_vcek_milan.cer
var sevSnpVcekMilan []byte

func newKDSReplay() trust.HTTPSGetter {
	return sevtest.SimpleGetter(map[string][]byte{
		"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": trust.AskArkMilanVcekBytes,
		"https://kdsintf.amd.com/vcek/v1/Milan/3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68": sevSnpVcekMilan,
	})
}

func fixedNow() time.Time {
	return time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
}

func realMeasurement() []byte { return sevSnpAttestationMilan[0x90 : 0x90+48] }
func realChipID() []byte      { return sevSnpAttestationMilan[0x1A0 : 0x1A0+64] }

func makeRIM(t *testing.T) [32]byte {
	t.Helper()
	return sha256.Sum256(realMeasurement())
}

func makeHardware(t *testing.T) [32]byte {
	t.Helper()
	return sha256.Sum256(realChipID())
}

func makeTEEPub(t *testing.T) [32]byte {
	t.Helper()
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i + 1)
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

func newTestFileHSM(t *testing.T) hsm.Provider {
	t.Helper()
	dir := t.TempDir()
	cfg := &hsm.FileConfig{
		BasePath:   dir,
		HexEncoded: true,
	}
	p, err := hsm.NewFileProvider(cfg)
	if err != nil {
		t.Fatalf("newTestFileHSM: %v", err)
	}
	var ed25519Seed [32]byte
	if _, err := rand.Read(ed25519Seed[:]); err != nil {
		t.Fatalf("ed25519 seed: %v", err)
	}
	if err := p.StoreKey(context.Background(), "audit-key", ed25519Seed[:]); err != nil {
		t.Fatalf("store audit key: %v", err)
	}
	t.Cleanup(func() {
		_ = p.Close()
		_ = os.RemoveAll(dir)
	})
	return p
}

func newTestApprovalProvider(t *testing.T) approval.ApprovalProvider {
	t.Helper()
	p, err := approval.NewProvider("local-dev", nil)
	if err != nil {
		t.Fatalf("newTestApprovalProvider: %v", err)
	}
	return p
}

// TestMain enables the LocalDevProvider for the lifetime of this
// test binary.
func TestMain(m *testing.M) {
	_ = os.Setenv("MPC_LOCAL_APPROVAL", "true")
	os.Exit(m.Run())
}

// denyApprovalProvider models user-cancel from a real WebAuthn/Ledger.
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

func newTestSigner(t *testing.T, approvalRequired bool) (*Signer, *kms.LocalReleaseGate, hsm.Provider, [32]byte, [32]byte) {
	t.Helper()
	rim := makeRIM(t)
	hw := makeHardware(t)

	gate, _ := newTestGate(t, rim, hw)
	hsmP := newTestFileHSM(t)
	appr := newTestApprovalProvider(t)

	cfg := Config{
		Threshold:        2,
		Participants:     3,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-key",
		ApprovalRequired: approvalRequired,
		ApproverID:       "test@lux.network",
	}
	s, err := New(gate, hsmP, appr, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Provision(context.Background()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return s, gate, hsmP, rim, hw
}

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
// Required test 1: full chain E2E
// ============================================================================

func TestSigner_Sign_SEVSNP_E2E(t *testing.T) {
	t.Parallel()
	s, _, _, rim, hw := newTestSigner(t, true)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	jobID, err := FreshJobID()
	if err != nil {
		t.Fatalf("FreshJobID: %v", err)
	}
	msg := []byte("LUX-RLWE-TEE: institutional-custody E2E test")

	wire, receipt, err := s.Sign(context.Background(), env, jobID, msg)
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
		t.Errorf("receipt.EvidenceKind = %q", receipt.EvidenceKind)
	}
	if receipt.EvidenceIssuer != kms.IssuerSEVSNP {
		t.Errorf("receipt.EvidenceIssuer = %q", receipt.EvidenceIssuer)
	}
	if len(receipt.AuditSignature) == 0 {
		t.Error("receipt.AuditSignature empty")
	}

	gk, err := s.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		t.Fatalf("gk.MarshalBinary: %v", err)
	}
	if !coronaThreshold.VerifyBytes(gkBytes, string(msg), wire) {
		t.Fatal("external VerifyBytes refused the corona threshold signature")
	}
}

// ============================================================================
// Required test 2: rejects corrupt attestation
// ============================================================================

func TestSigner_Sign_RejectsBadAttestation(t *testing.T) {
	t.Parallel()
	s, _, _, rim, hw := newTestSigner(t, false)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	env.EvidenceBytes[0x2A0+0x10] ^= 0x01

	jobID, _ := FreshJobID()
	msg := []byte("reject-bad-evidence")
	_, _, err := s.Sign(context.Background(), env, jobID, msg)
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

func TestSigner_Sign_RejectsRIMMismatch(t *testing.T) {
	t.Parallel()
	s, _, _, _, hw := newTestSigner(t, false)
	teePub := makeTEEPub(t)

	wrongRIM := sha256.Sum256([]byte("not-the-real-measurement"))
	env := envelopeFromTestdata(t, wrongRIM, hw, teePub)

	jobID, _ := FreshJobID()
	msg := []byte("reject-wrong-rim")
	_, _, err := s.Sign(context.Background(), env, jobID, msg)
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

func TestSigner_Sign_RejectsExpiredNonce(t *testing.T) {
	t.Parallel()
	s, gate, _, rim, hw := newTestSigner(t, false)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	gate.SetIssueTTL(10 * time.Millisecond)

	jobID, _ := FreshJobID()
	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	env.ExpectedNonce = nonce
	time.Sleep(50 * time.Millisecond)

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

	gate.SetIssueTTL(5 * time.Second)
	_ = gate.Rotate()
	freshJob, _ := FreshJobID()
	freshEnv := envelopeFromTestdata(t, rim, hw, teePub)
	msg := []byte("post-rotation-sign")
	if _, _, err := s.Sign(context.Background(), freshEnv, freshJob, msg); err != nil {
		t.Fatalf("Sign post-rotation: %v", err)
	}
}

// ============================================================================
// Required test 5: AWS KMS backend
// ============================================================================

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

func TestSigner_Sign_HSMSign_File(t *testing.T) {
	t.Parallel()
	s, _, _, rim, hw := newTestSigner(t, true)
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)

	jobID, _ := FreshJobID()
	msg := []byte("file-hsm-e2e")
	wire, _, err := s.Sign(context.Background(), env, jobID, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	gk, err := s.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		t.Fatalf("gk.MarshalBinary: %v", err)
	}
	if !coronaThreshold.VerifyBytes(gkBytes, string(msg), wire) {
		t.Fatal("file-hsm-e2e: VerifyBytes refused corona threshold signature")
	}
}

// ============================================================================
// Required test 7: WebAuthn-style approval required
// ============================================================================

func TestSigner_Sign_ApprovalRequired_DenyAndAllow(t *testing.T) {
	t.Parallel()
	rim := makeRIM(t)
	hw := makeHardware(t)
	gate, store := newTestGate(t, rim, hw)
	fileP := newTestFileHSM(t)

	cfg := Config{
		Threshold:        2,
		Participants:     3,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-key",
		ApprovalRequired: true,
		ApproverID:       "ceo@lux.network",
	}

	denyS, err := New(gate, fileP, denyApprovalProvider{}, cfg)
	if err != nil {
		t.Fatalf("New(deny): %v", err)
	}
	if _, err := denyS.Provision(context.Background()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	teePub := makeTEEPub(t)
	env := envelopeFromTestdata(t, rim, hw, teePub)
	jobID, _ := FreshJobID()
	msg := []byte("approval-deny-test")
	_, _, err = denyS.Sign(context.Background(), env, jobID, msg)
	if err == nil {
		t.Fatal("Sign(deny): expected ErrApprovalDenied, got nil")
	}
	if !errors.Is(err, ErrApprovalDenied) {
		t.Errorf("Sign(deny): err = %v, want wrapped ErrApprovalDenied", err)
	}
	if _, lookupErr := store.Lookup(jobID); !errors.Is(lookupErr, kms.ErrNonceUnknown) {
		t.Errorf("deny path leaked a gate-issued nonce: %v", lookupErr)
	}

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
	if _, _, err := allowS.Sign(context.Background(), allowEnv, allowJob, msg); err != nil {
		t.Fatalf("Sign(allow): %v", err)
	}
}

// ============================================================================
// Config validation
// ============================================================================

func TestConfig_Validate(t *testing.T) {
	rim := [32]byte{1}
	hw := [32]byte{2}
	good := Config{
		Threshold:        2,
		Participants:     3,
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
		{"thresholdZero", func(c *Config) { c.Threshold = 0 }, ErrInvalidThreshold},
		{"thresholdEqualParticipants", func(c *Config) { c.Threshold = 3 }, ErrInvalidThreshold},
		{"participantsTooLow", func(c *Config) { c.Threshold = 1; c.Participants = 1 }, ErrInvalidThreshold},
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

func TestSigner_ThresholdAndParticipants(t *testing.T) {
	t.Parallel()
	s, _, _, _, _ := newTestSigner(t, false)
	if got := s.Threshold(); got != 2 {
		t.Errorf("Threshold = %d, want 2", got)
	}
	if got := s.Participants(); got != 3 {
		t.Errorf("Participants = %d, want 3", got)
	}
}
