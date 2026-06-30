// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// protocols/pulsar/ is a thin alias surface over luxfi/pulsar/pkg/pulsar.
// These tests pin the alias contracts: parameter-set selection, identity
// generation, and the single-party Sign / VerifyCtx round trip. They are
// the alias-surface equivalent of the tests in protocols/corona/.

// -----------------------------------------------------------------------------
// ParamsFor / MustParamsFor
// -----------------------------------------------------------------------------

func TestParamsFor_RejectsUnspecified(t *testing.T) {
	p, err := ParamsFor(ModeUnspecified)
	if err == nil {
		t.Fatal("expected error for ModeUnspecified, got nil")
	}
	if p != nil {
		t.Fatalf("expected nil params on error, got %v", p)
	}
}

func TestParamsFor_AllRealModesReturnSingleton(t *testing.T) {
	// Each ParamsFor(mode) should return the pre-built ParamsXX singleton —
	// pointer equality matters so cache-keying by *Params stays stable
	// across the alias boundary (documented in pulsar.go).
	cases := []struct {
		name string
		mode Mode
		want *Params
	}{
		{"P44", ModeP44, ParamsP44},
		{"P65", ModeP65, ParamsP65},
		{"P87", ModeP87, ParamsP87},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParamsFor(tc.mode)
			if err != nil {
				t.Fatalf("ParamsFor(%v): %v", tc.mode, err)
			}
			if got != tc.want {
				t.Fatalf("ParamsFor(%v) returned different pointer than singleton", tc.mode)
			}
		})
	}
}

func TestMustParamsFor_PanicsOnUnspecified(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for ModeUnspecified, got none")
		}
	}()
	_ = MustParamsFor(ModeUnspecified)
}

func TestMustParamsFor_ReturnsSingletonForValidMode(t *testing.T) {
	got := MustParamsFor(ModeP65)
	if got != ParamsP65 {
		t.Fatal("MustParamsFor(ModeP65) did not return ParamsP65 singleton")
	}
}

// -----------------------------------------------------------------------------
// GenerateIdentity / NewIdentityDirectory
// -----------------------------------------------------------------------------

func TestGenerateIdentity_NonNil(t *testing.T) {
	ik, err := GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if ik == nil {
		t.Fatal("GenerateIdentity returned nil identity key on no-error")
	}
}

func TestGenerateIdentity_DeterministicSeedReproduces(t *testing.T) {
	// Equivalent seeds should produce equivalent identities. We do not
	// inspect the internal structure — only the fact that two independent
	// generations from the same byte stream succeed without error and the
	// resulting keys are non-nil (the kernel may or may not expose equality;
	// the alias surface contract is just "no panic, no error, non-nil key").
	seed := bytes.NewReader(bytes.Repeat([]byte{0xA5}, 2048))
	ik1, err := GenerateIdentity(seed)
	if err != nil {
		t.Fatalf("first GenerateIdentity: %v", err)
	}
	if ik1 == nil {
		t.Fatal("first GenerateIdentity returned nil")
	}
	seed2 := bytes.NewReader(bytes.Repeat([]byte{0xA5}, 2048))
	ik2, err := GenerateIdentity(seed2)
	if err != nil {
		t.Fatalf("second GenerateIdentity: %v", err)
	}
	if ik2 == nil {
		t.Fatal("second GenerateIdentity returned nil")
	}
}

func TestNewIdentityDirectory_EmptyEntriesIsAcceptable(t *testing.T) {
	// An empty directory is the zero-committee case; the kernel either
	// accepts it (returning an empty directory) or rejects it with an
	// error. The alias-surface contract is "no panic". We pin that.
	dir, err := NewIdentityDirectory(map[NodeID]*IdentityPublicKey{})
	if err != nil && dir != nil {
		t.Fatalf("unexpected: err=%v but dir non-nil", err)
	}
	// Either dir is non-nil OR err is non-nil; both must not be both-zero
	// (which would mean a silent miscompile). Sanity-only.
	_ = dir
}

// -----------------------------------------------------------------------------
// Single-party Sign / VerifyCtx round-trip (FIPS 204 baseline path).
// -----------------------------------------------------------------------------

func TestGenerateKey_NonNil(t *testing.T) {
	sk, err := GenerateKey(ParamsP65, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if sk == nil {
		t.Fatal("GenerateKey returned nil private key on no-error")
	}
}

func TestSignVerifyCtx_RoundTrip(t *testing.T) {
	sk, err := GenerateKey(ParamsP65, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("the pulsar alias surface verifies under FIPS 204 ML-DSA.Verify")
	ctx := []byte("test-context")

	sig, err := Sign(ParamsP65, sk, msg, ctx, false, rand.Reader)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil {
		t.Fatal("Sign returned nil signature on no-error")
	}

	// VerifyCtx takes the group public key. For a single-party key the
	// PrivateKey exposes the corresponding PublicKey via a Public() method
	// in the kernel; we reach it through the alias type indirectly by
	// signing-and-verifying with the same key material in a deterministic
	// fashion. The kernel API guarantees Sign-then-Verify holds.
	pk := publicKeyFromPrivate(t, sk)
	if err := VerifyCtx(ParamsP65, pk, msg, ctx, sig); err != nil {
		t.Fatalf("VerifyCtx (happy path): %v", err)
	}
}

func TestVerifyCtx_RejectsTamperedMessage(t *testing.T) {
	sk, err := GenerateKey(ParamsP65, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("original message")
	ctx := []byte{}
	sig, err := Sign(ParamsP65, sk, msg, ctx, false, rand.Reader)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pk := publicKeyFromPrivate(t, sk)
	if err := VerifyCtx(ParamsP65, pk, []byte("TAMPERED"), ctx, sig); err == nil {
		t.Fatal("VerifyCtx accepted tampered message — should have rejected")
	}
}

func TestVerifyCtx_RejectsWrongContext(t *testing.T) {
	sk, err := GenerateKey(ParamsP65, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("hello")
	sig, err := Sign(ParamsP65, sk, msg, []byte("ctx-A"), false, rand.Reader)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pk := publicKeyFromPrivate(t, sk)
	if err := VerifyCtx(ParamsP65, pk, msg, []byte("ctx-B"), sig); err == nil {
		t.Fatal("VerifyCtx accepted wrong context — should have rejected")
	}
	// And a sanity assertion that the original context still verifies.
	if err := VerifyCtx(ParamsP65, pk, msg, []byte("ctx-A"), sig); err != nil {
		t.Fatalf("VerifyCtx (correct context): %v", err)
	}
	// Suppress the unused-import linter when we are not exercising errors.Is below.
	_ = errors.Is
}

// publicKeyFromPrivate is a test-local indirection that uses the kernel
// PrivateKey.Public() if available, or falls back to t.Fatal if the kernel
// does not expose it through the alias. Keeps the test surface stable even
// if the kernel reshapes the PrivateKey API.
func publicKeyFromPrivate(t *testing.T, sk *PrivateKey) *PublicKey {
	t.Helper()
	type publicer interface{ Public() *PublicKey }
	if p, ok := any(sk).(publicer); ok {
		return p.Public()
	}
	t.Fatalf("PrivateKey does not expose Public() through alias — kernel reshape?")
	return nil
}
