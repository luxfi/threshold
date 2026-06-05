// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"context"
	"testing"
	"time"

	luxmldsa "github.com/luxfi/crypto/mldsa"
	luxslhdsa "github.com/luxfi/crypto/slhdsa"
	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"
)

// sign_ctx_test.go — ZAP-driven Sign_Ctx tests. The prior HTTP+JSON
// test harness was deleted alongside the HTTP path; cryptographic
// correctness across the ZAP wire is asserted here.

// precompileCtxMLDSA is the FIPS 204 §5.2 ctx string that the on-chain
// ML-DSA precompile (luxfi/precompile/mldsa, address 0x012202) binds
// via pub.VerifySignatureCtx. A signature emitted by pulsar.sign_ctx
// with this ctx MUST be accepted by the same primitive the precompile
// calls; a signature with any other (or empty) ctx MUST be rejected.
var precompileCtxMLDSA = []byte("lux-evm-precompile-mldsa-v1")

// precompileCtxSLHDSA is the corresponding FIPS 205 §10.2 ctx for the
// SLH-DSA precompile (luxfi/precompile/slhdsa, address 0x012203).
var precompileCtxSLHDSA = []byte("lux-evm-precompile-slhdsa-v1")

// TestPulsar_Sign_Ctx_MatchesPrecompileVerify drives the full
// end-to-end chain that the EVM ML-DSA precompile takes:
//
//  1. Dispatch pulsar.keygen → published PULG-framed group public key.
//  2. Dispatch pulsar.sign_ctx with ctx = `lux-evm-precompile-mldsa-v1`.
//  3. Strip the PULG / PULS frames to recover the raw FIPS 204 bytes
//     the precompile would receive on-chain (calldata is unframed).
//  4. Call luxfi/crypto/mldsa.PublicKey.VerifySignatureCtx — this is
//     the EXACT primitive luxfi/precompile/mldsa.Run() calls, so this
//     surface IS the on-chain precompile minus the calldata-parsing
//     wrapper.
//  5. Assert accept on the precompile ctx; reject on the empty ctx
//     and on a wrong ctx.
func TestPulsar_Sign_Ctx_MatchesPrecompileVerify(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping Pulsar sign_ctx precompile cross-check under -short")
	}
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKeyBytes, _, err := c.Keygen(ctx, "pulsar", 2, 3)
	if err != nil {
		t.Fatalf("pulsar.keygen: %v", err)
	}
	if len(pubKeyBytes) == 0 {
		t.Fatal("pulsar.keygen: empty publicKey")
	}

	msg := []byte("pulsar sign_ctx -> precompile.VerifyCtx accept")
	sigBytes, err := c.SignCtx(ctx, "pulsar", msg, pubKeyBytes, precompileCtxMLDSA, "")
	if err != nil {
		t.Fatalf("pulsar.sign_ctx: %v", err)
	}

	// Strip PULG / PULS frames to recover raw FIPS 204 bytes.
	var pub pulsar.PublicKey
	if err := pub.UnmarshalBinary(pubKeyBytes); err != nil {
		t.Fatalf("PULG UnmarshalBinary: %v", err)
	}
	var sig pulsar.Signature
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		t.Fatalf("PULS UnmarshalBinary: %v", err)
	}

	if pub.Mode != pulsar.ModeP65 {
		t.Fatalf("unexpected pubkey mode %v, want %v", pub.Mode, pulsar.ModeP65)
	}

	luxPub, err := luxmldsa.PublicKeyFromBytes(pub.Bytes, luxmldsa.MLDSA65)
	if err != nil {
		t.Fatalf("luxmldsa.PublicKeyFromBytes: %v", err)
	}

	// Accept: precompile ctx
	if !luxPub.VerifySignatureCtx(msg, sig.Bytes, precompileCtxMLDSA) {
		t.Fatalf("precompile rejected the dispatcher-bound ctx")
	}

	// Reject: empty ctx. Proves ctx binding is load-bearing.
	if luxPub.VerifySignatureCtx(msg, sig.Bytes, nil) {
		t.Fatalf("precompile accepted empty ctx — ctx is NOT propagated")
	}

	// Reject: wrong ctx.
	if luxPub.VerifySignatureCtx(msg, sig.Bytes, []byte("lux-evm-precompile-wrong-v1")) {
		t.Fatalf("precompile accepted wrong ctx")
	}
}

// TestMagnetar_Sign_Ctx_MatchesPrecompileVerify is the FIPS 205
// counterpart: magnetar.sign_ctx → MAGS frame → raw FIPS 205 bytes →
// luxfi/crypto/slhdsa.PublicKey.VerifySignatureCtx (the same primitive
// the on-chain SLH-DSA precompile calls).
//
// 1-of-1 keeps the test fast — the magnetar v0.5 primary primitive
// IS per-validator standalone, so threshold/participants is purely
// a session-cardinality knob.
func TestMagnetar_Sign_Ctx_MatchesPrecompileVerify(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping Magnetar sign_ctx precompile cross-check under -short")
	}
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKeyBytes, _, err := c.Keygen(ctx, "magnetar", 1, 1)
	if err != nil {
		t.Fatalf("magnetar.keygen: %v", err)
	}
	if len(pubKeyBytes) == 0 {
		t.Fatal("magnetar.keygen: empty publicKey")
	}

	msg := []byte("magnetar sign_ctx -> precompile.VerifyCtx accept")
	sigBytes, err := c.SignCtx(ctx, "magnetar", msg, pubKeyBytes, precompileCtxSLHDSA, "")
	if err != nil {
		t.Fatalf("magnetar.sign_ctx: %v", err)
	}

	pub, err := magnetar.UnmarshalGroupKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("MAGG UnmarshalGroupKey: %v", err)
	}
	var sig magnetar.Signature
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		t.Fatalf("MAGS UnmarshalBinary: %v", err)
	}

	if pub.Mode != magnetar.ModeM192s {
		t.Fatalf("unexpected pubkey mode %v, want %v", pub.Mode, magnetar.ModeM192s)
	}

	luxPub, err := luxslhdsa.PublicKeyFromBytes(pub.Bytes, luxslhdsa.SHAKE_192s)
	if err != nil {
		t.Fatalf("luxslhdsa.PublicKeyFromBytes: %v", err)
	}

	// Accept
	if !luxPub.VerifySignatureCtx(msg, sig.Bytes, precompileCtxSLHDSA) {
		t.Fatal("precompile rejected the dispatcher-bound ctx")
	}
	// Reject: empty ctx
	if luxPub.VerifySignatureCtx(msg, sig.Bytes, nil) {
		t.Fatal("precompile accepted empty ctx — ctx is NOT propagated")
	}
	// Reject: wrong ctx
	if luxPub.VerifySignatureCtx(msg, sig.Bytes, []byte("lux-evm-precompile-wrong-v1")) {
		t.Fatal("precompile accepted wrong ctx")
	}
}

// TestPulsar_Sign_Ctx_EmptyCtxMatchesPlainSign asserts that
// sign_ctx with an empty ctx parameter produces a signature that
// verifies under empty-ctx verify (i.e., behaves as a vanilla FIPS
// 204 sign).
func TestPulsar_Sign_Ctx_EmptyCtxMatchesPlainSign(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping Pulsar empty-ctx parity under -short")
	}
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "pulsar", 2, 3)
	if err != nil {
		t.Fatalf("pulsar.keygen: %v", err)
	}
	msg := []byte("pulsar sign_ctx empty-ctx parity")
	sig, err := c.SignCtx(ctx, "pulsar", msg, pubKey, nil, "")
	if err != nil {
		t.Fatalf("pulsar.sign_ctx: %v", err)
	}
	ok, err := c.Verify(ctx, "pulsar", msg, sig, pubKey)
	if err != nil {
		t.Fatalf("pulsar.verify: %v", err)
	}
	if !ok {
		t.Fatal("empty-ctx sign_ctx output failed stateless empty-ctx verify")
	}
}

// TestMagnetar_Sign_Ctx_EmptyCtxMatchesPlainSign is the magnetar
// counterpart of the empty-ctx parity test above.
func TestMagnetar_Sign_Ctx_EmptyCtxMatchesPlainSign(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping Magnetar empty-ctx parity under -short")
	}
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "magnetar", 1, 1)
	if err != nil {
		t.Fatalf("magnetar.keygen: %v", err)
	}
	msg := []byte("magnetar sign_ctx empty-ctx parity")
	sig, err := c.SignCtx(ctx, "magnetar", msg, pubKey, nil, "")
	if err != nil {
		t.Fatalf("magnetar.sign_ctx: %v", err)
	}
	ok, err := c.Verify(ctx, "magnetar", msg, sig, pubKey)
	if err != nil {
		t.Fatalf("magnetar.verify: %v", err)
	}
	if !ok {
		t.Fatal("empty-ctx sign_ctx output failed stateless empty-ctx verify")
	}
}

// TestSign_Ctx_UnsupportedSchemeReturnsMethodNotFound asserts that
// schemes that do NOT implement ctxSigner surface a method-not-found
// error rather than silently routing to a non-existent handler. The
// ZAP wire encodes this as ZapErrCodeMethodNotFnd in the error
// envelope.
func TestSign_Ctx_UnsupportedSchemeReturnsMethodNotFound(t *testing.T) {
	t.Parallel()
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	// cggmp21/frost/bls/corona/doerner do NOT register sign_ctx
	// procedures in allProcedures, so knownProcedure rejects on the
	// client side. That is the canonical method-not-found path: the
	// client refuses to round-trip a procedure it does not know.
	for _, sch := range []string{"cggmp21", "frost", "bls", "corona", "doerner"} {
		_, err := c.SignCtx(ctx, sch, []byte{0}, []byte{0}, []byte{0}, "")
		if err == nil {
			t.Fatalf("%s.sign_ctx: expected error, got success", sch)
		}
	}
}
