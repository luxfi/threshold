// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

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

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"

	coronaThreshold "github.com/luxfi/corona/threshold"

	"github.com/luxfi/mpc/pkg/approval"
	"github.com/luxfi/mpc/pkg/hsm"
	"github.com/luxfi/mpc/pkg/kms"

	mldsatee "github.com/luxfi/threshold/protocols/mldsa-tee"
	rlwetee "github.com/luxfi/threshold/protocols/rlwe-tee"
	slhdsatee "github.com/luxfi/threshold/protocols/slhdsa-tee"
)

// sevSnpAttestationMilan and sevSnpVcekMilan — committed AMD Milan
// fixtures (same bytes as the lux/mpc cc/attest test corpus).
//
//go:embed testdata/sev_snp_attestation_milan.bin
var sevSnpAttestationMilanDispatch []byte

//go:embed testdata/sev_snp_vcek_milan.cer
var sevSnpVcekMilanDispatch []byte

func dispatchKDSReplay() trust.HTTPSGetter {
	return sevtest.SimpleGetter(map[string][]byte{
		"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": trust.AskArkMilanVcekBytes,
		"https://kdsintf.amd.com/vcek/v1/Milan/3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68": sevSnpVcekMilanDispatch,
	})
}

func dispatchFixedNow() time.Time {
	return time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
}

func dispatchMakeFileHSM(t *testing.T) hsm.Provider {
	t.Helper()
	dir := t.TempDir()
	p, err := hsm.NewFileProvider(&hsm.FileConfig{
		BasePath:   dir,
		HexEncoded: true,
	})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}
	var ed25519Seed [32]byte
	if _, err := rand.Read(ed25519Seed[:]); err != nil {
		t.Fatalf("ed25519 seed: %v", err)
	}
	if err := p.StoreKey(context.Background(), "audit-key", ed25519Seed[:]); err != nil {
		t.Fatalf("store audit: %v", err)
	}
	t.Cleanup(func() {
		_ = p.Close()
		_ = os.RemoveAll(dir)
	})
	return p
}

func dispatchMakeGate(t *testing.T, rim, hw [32]byte) *kms.LocalReleaseGate {
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

// MPC_LOCAL_APPROVAL=true is exported by the package's existing
// TestMain (thresholdd_test.go).

// realRIM / realHardware mirror the per-package helpers.
func realRIM() [32]byte {
	return sha256.Sum256(sevSnpAttestationMilanDispatch[0x90 : 0x90+48])
}

func realHardware() [32]byte {
	return sha256.Sum256(sevSnpAttestationMilanDispatch[0x1A0 : 0x1A0+64])
}

// TestMagnetar_Sign_TEE_Dispatch wires a real slhdsatee.Signer into
// the magnetar dispatcher, drives Sign_TEE end-to-end, and asserts
// the returned wire bytes verify under magnetar.VerifyBytes against
// the in-memory public key.
func TestMagnetar_Sign_TEE_Dispatch(t *testing.T) {
	rim := realRIM()
	hw := realHardware()
	gate := dispatchMakeGate(t, rim, hw)
	hsmP := dispatchMakeFileHSM(t)
	appr, err := approval.NewProvider("local-dev", nil)
	if err != nil {
		t.Fatalf("local-dev: %v", err)
	}

	cfg := slhdsatee.Config{
		Mode:             magnetar.ModeM192s,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-seed",
		ApprovalRequired: false, // single-flow test
	}
	signer, err := slhdsatee.New(gate, hsmP, appr, cfg)
	if err != nil {
		t.Fatalf("slhdsatee.New: %v", err)
	}
	pub, err := signer.Provision(context.Background(), nil)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	sch := newMagnetarScheme()

	// Unwired Sign_TEE must refuse.
	_, _, err = sch.Sign_TEE(context.Background(), "sev_snp", sevSnpAttestationMilanDispatch,
		rim, hw, [32]byte{}, nil, [32]byte{}, []byte("x"), nil)
	if !errors.Is(err, errMagnetarTEEUnwired) {
		t.Fatalf("expected errMagnetarTEEUnwired, got %v", err)
	}

	sch.SetTEEBackend(signer)

	var teePub [32]byte
	for i := range teePub {
		teePub[i] = byte(i + 17)
	}
	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	msg := []byte("dispatcher-tee-magnetar")

	verifyOpts := []TEEVerifyOption{
		WithKDSGetter(dispatchKDSReplay()),
		WithNow(dispatchFixedNow()),
	}
	wire, audit, err := sch.Sign_TEE(context.Background(), "sev_snp", sevSnpAttestationMilanDispatch,
		rim, hw, teePub, verifyOpts, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Sign_TEE: %v", err)
	}
	if len(wire) == 0 || len(audit) == 0 {
		t.Fatal("Sign_TEE returned empty payload")
	}

	gkBytes, err := magnetar.MarshalGroupKey(pub)
	if err != nil {
		t.Fatalf("MarshalGroupKey: %v", err)
	}
	if !magnetar.VerifyBytes(gkBytes, msg, wire) {
		t.Fatal("Sign_TEE output failed external VerifyBytes")
	}
}

// TestPulsar_Sign_TEE_Dispatch — same shape, FIPS 204 backend.
func TestPulsar_Sign_TEE_Dispatch(t *testing.T) {
	rim := realRIM()
	hw := realHardware()
	gate := dispatchMakeGate(t, rim, hw)
	hsmP := dispatchMakeFileHSM(t)
	appr, err := approval.NewProvider("local-dev", nil)
	if err != nil {
		t.Fatalf("local-dev: %v", err)
	}

	cfg := mldsatee.Config{
		Mode:             pulsar.ModeP65,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-seed",
		ApprovalRequired: false,
	}
	signer, err := mldsatee.New(gate, hsmP, appr, cfg)
	if err != nil {
		t.Fatalf("mldsatee.New: %v", err)
	}
	pub, err := signer.Provision(context.Background())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	sch := newPulsarScheme()

	// Unwired refuse.
	_, _, err = sch.Sign_TEE(context.Background(), "sev_snp", sevSnpAttestationMilanDispatch,
		rim, hw, [32]byte{}, nil, [32]byte{}, []byte("x"), nil)
	if !errors.Is(err, errPulsarTEEUnwired) {
		t.Fatalf("expected errPulsarTEEUnwired, got %v", err)
	}

	sch.SetTEEBackend(signer)

	var teePub [32]byte
	for i := range teePub {
		teePub[i] = byte(i + 17)
	}
	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	msg := []byte("dispatcher-tee-pulsar")

	verifyOpts := []TEEVerifyOption{
		WithKDSGetter(dispatchKDSReplay()),
		WithNow(dispatchFixedNow()),
	}
	wire, audit, err := sch.Sign_TEE(context.Background(), "sev_snp", sevSnpAttestationMilanDispatch,
		rim, hw, teePub, verifyOpts, jobID, msg, nil)
	if err != nil {
		t.Fatalf("Sign_TEE: %v", err)
	}
	if len(wire) == 0 || len(audit) == 0 {
		t.Fatal("Sign_TEE returned empty payload")
	}
	gkBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("pub.MarshalBinary: %v", err)
	}
	if !pulsar.VerifyBytes(gkBytes, msg, wire) {
		t.Fatal("Sign_TEE output failed external VerifyBytes")
	}
}

// TestCorona_Sign_TEE_Dispatch — same shape, corona Ring-LWE backend.
func TestCorona_Sign_TEE_Dispatch(t *testing.T) {
	rim := realRIM()
	hw := realHardware()
	gate := dispatchMakeGate(t, rim, hw)
	hsmP := dispatchMakeFileHSM(t)
	appr, err := approval.NewProvider("local-dev", nil)
	if err != nil {
		t.Fatalf("local-dev: %v", err)
	}

	cfg := rlwetee.Config{
		Threshold:        2,
		Participants:     3,
		RequiredRIM:      map[[32]byte]struct{}{rim: {}},
		AllowedHardware:  map[[32]byte]struct{}{hw: {}},
		RequireSEVSNP:    true,
		KMSKeyID:         "audit-key",
		WrappedSeedKeyID: "master-key",
		ApprovalRequired: false,
	}
	signer, err := rlwetee.New(gate, hsmP, appr, cfg)
	if err != nil {
		t.Fatalf("rlwetee.New: %v", err)
	}
	gk, err := signer.Provision(context.Background())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	sch := newCoronaScheme()

	_, _, err = sch.Sign_TEE(context.Background(), "sev_snp", sevSnpAttestationMilanDispatch,
		rim, hw, [32]byte{}, nil, [32]byte{}, []byte("x"))
	if !errors.Is(err, errCoronaTEEUnwired) {
		t.Fatalf("expected errCoronaTEEUnwired, got %v", err)
	}

	sch.SetTEEBackend(signer)

	var teePub [32]byte
	for i := range teePub {
		teePub[i] = byte(i + 17)
	}
	var jobID [32]byte
	if _, err := rand.Read(jobID[:]); err != nil {
		t.Fatalf("jobID: %v", err)
	}
	msg := []byte("dispatcher-tee-corona")

	verifyOpts := []TEEVerifyOption{
		WithKDSGetter(dispatchKDSReplay()),
		WithNow(dispatchFixedNow()),
	}
	wire, audit, err := sch.Sign_TEE(context.Background(), "sev_snp", sevSnpAttestationMilanDispatch,
		rim, hw, teePub, verifyOpts, jobID, msg)
	if err != nil {
		t.Fatalf("Sign_TEE: %v", err)
	}
	if len(wire) == 0 || len(audit) == 0 {
		t.Fatal("Sign_TEE returned empty payload")
	}
	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		t.Fatalf("gk.MarshalBinary: %v", err)
	}
	if !coronaThreshold.VerifyBytes(gkBytes, string(msg), wire) {
		t.Fatal("Sign_TEE output failed external VerifyBytes")
	}

	// Defence: passing a custom kind not in our enum maps through to
	// cc/attest.Dispatch which returns ErrUnsupportedKind. The release
	// gate's VerifyEvidence step calls Dispatch; rlwetee.ErrPolicyRefused
	// is the canonical wrap so we assert that sentinel. The inner
	// ErrUnsupportedKind appears in err.Error() but isn't surfaced via
	// errors.Is because the gate joins via %v not %w (kms upstream API).
	var jobID2 [32]byte
	if _, err := rand.Read(jobID2[:]); err != nil {
		t.Fatalf("jobID2: %v", err)
	}
	_, _, err = sch.Sign_TEE(context.Background(), "unknown-kind", sevSnpAttestationMilanDispatch,
		rim, hw, teePub, verifyOpts, jobID2, msg)
	if err == nil {
		t.Fatal("Sign_TEE: expected error on unknown kind")
	}
	if !errors.Is(err, rlwetee.ErrPolicyRefused) {
		t.Errorf("Sign_TEE: err = %v, want wrapped rlwetee.ErrPolicyRefused", err)
	}
}
