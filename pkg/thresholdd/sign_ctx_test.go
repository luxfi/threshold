// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	luxmldsa "github.com/luxfi/crypto/mldsa"
	luxslhdsa "github.com/luxfi/crypto/slhdsa"
	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"
)

// precompileCtxMLDSA is the FIPS 204 §5.2 ctx string that the on-chain
// ML-DSA precompile (luxfi/precompile/mldsa, address 0x012202) binds
// via pub.VerifySignatureCtx. A signature emitted by pulsar.sign_ctx
// with this ctx MUST be accepted by the same primitive the precompile
// calls; a signature with any other (or empty) ctx MUST be rejected.
var precompileCtxMLDSA = []byte("lux-evm-precompile-mldsa-v1")

// precompileCtxSLHDSA is the corresponding FIPS 205 §10.2 ctx for the
// SLH-DSA precompile (luxfi/precompile/slhdsa, address 0x012203).
var precompileCtxSLHDSA = []byte("lux-evm-precompile-slhdsa-v1")

// signCtxRPCCall posts a <scheme>.sign_ctx request and returns the
// hex signature. It uses raw http instead of rpcCall so we can drive
// the exact JSON envelope (rpcCall hides typed param/result mapping).
func signCtxRPCCall(t *testing.T, url, scheme, msgHex, pkHex, ctxHex string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": scheme + ".sign_ctx",
		"params": map[string]any{
			"messageHex": msgHex,
			"pubKeyHex":  pkHex,
			"ctxHex":     ctxHex,
		},
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var env struct {
		Result *signResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error != nil {
		t.Fatalf("rpc error %d: %s", env.Error.Code, env.Error.Message)
	}
	if env.Result == nil || env.Result.SignatureHex == "" {
		t.Fatalf("empty signature")
	}
	return env.Result.SignatureHex
}

// TestPulsar_Sign_Ctx_MatchesPrecompileVerify drives the full
// end-to-end chain that the EVM ML-DSA precompile takes:
//
//  1. Dispatch pulsar.keygen → published PULG-framed group public key.
//  2. Dispatch pulsar.sign_ctx with ctx = `lux-evm-precompile-mldsa-v1`.
//  3. Strip the PULG / PULS frames to recover the raw FIPS 204 bytes
//     the precompile would receive on-chain (calldata is unframed).
//  4. Call luxfi/crypto/mldsa.PublicKey.VerifySignatureCtx — this is
//     the EXACT primitive luxfi/precompile/mldsa.Run() calls (see
//     ~/work/lux/precompile/mldsa/contract.go:246), so this surface
//     IS the on-chain precompile minus the calldata-parsing wrapper.
//  5. Assert accept (byte(1)) on the precompile ctx; reject (byte(0))
//     on the empty ctx and on a wrong ctx.
//
// The byte(1)/byte(0) values mirror the precompile's 32-byte result
// word where result[31] is the truth flag (contract.go:251-253).
func TestPulsar_Sign_Ctx_MatchesPrecompileVerify(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()

	// Keygen produces the dispatcher-side session and publishes the
	// PULG-framed group public key. 2-of-3 is the canonical smoke
	// shape (matches TestPulsarRoundTrip).
	var kg keygenResult
	rpcCall(t, url, "pulsar.keygen", map[string]any{
		"threshold":    2,
		"participants": 3,
	}, &kg)
	if kg.PublicKey == "" {
		t.Fatal("pulsar.keygen: empty publicKey")
	}

	msg := []byte("pulsar sign_ctx -> precompile.VerifyCtx accept")
	msgHex := hex.EncodeToString(msg)
	ctxHex := hex.EncodeToString(precompileCtxMLDSA)

	sigHex := signCtxRPCCall(t, url, "pulsar", msgHex, kg.PublicKey, ctxHex)

	// Strip PULG / PULS frames to recover raw FIPS 204 bytes.
	gkBytes, err := hex.DecodeString(kg.PublicKey)
	if err != nil {
		t.Fatalf("decode pubKey hex: %v", err)
	}
	var pub pulsar.PublicKey
	if err := pub.UnmarshalBinary(gkBytes); err != nil {
		t.Fatalf("PULG UnmarshalBinary: %v", err)
	}
	sigFrameBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode sig hex: %v", err)
	}
	var sig pulsar.Signature
	if err := sig.UnmarshalBinary(sigFrameBytes); err != nil {
		t.Fatalf("PULS UnmarshalBinary: %v", err)
	}

	// The dispatcher's pulsar scheme ALWAYS runs in ModeP65 (see
	// pulsar.go: pulsar.MustParamsFor(pulsar.ModeP65) in Keygen).
	if pub.Mode != pulsar.ModeP65 {
		t.Fatalf("unexpected pubkey mode %v, want %v", pub.Mode, pulsar.ModeP65)
	}

	// Call the EXACT primitive the precompile dispatches to.
	luxPub, err := luxmldsa.PublicKeyFromBytes(pub.Bytes, luxmldsa.MLDSA65)
	if err != nil {
		t.Fatalf("luxmldsa.PublicKeyFromBytes: %v", err)
	}

	// Accept: precompile ctx → byte(1)
	acceptOK := luxPub.VerifySignatureCtx(msg, sig.Bytes, precompileCtxMLDSA)
	var acceptByte byte
	if acceptOK {
		acceptByte = 1
	}
	if acceptByte != byte(1) {
		t.Fatalf("precompile accept-byte = %d, want byte(1)", acceptByte)
	}

	// Reject 1: empty ctx → byte(0). Proves ctx binding is
	// load-bearing in the dispatcher path (a sig produced with
	// non-empty ctx must NOT verify under empty ctx).
	rejectEmptyOK := luxPub.VerifySignatureCtx(msg, sig.Bytes, nil)
	var rejectEmptyByte byte
	if rejectEmptyOK {
		rejectEmptyByte = 1
	}
	if rejectEmptyByte != byte(0) {
		t.Fatalf("precompile empty-ctx reject-byte = %d, want byte(0) — ctx is NOT propagated", rejectEmptyByte)
	}

	// Reject 2: wrong ctx → byte(0).
	wrongCtx := []byte("lux-evm-precompile-wrong-v1")
	rejectWrongOK := luxPub.VerifySignatureCtx(msg, sig.Bytes, wrongCtx)
	var rejectWrongByte byte
	if rejectWrongOK {
		rejectWrongByte = 1
	}
	if rejectWrongByte != byte(0) {
		t.Fatalf("precompile wrong-ctx reject-byte = %d, want byte(0)", rejectWrongByte)
	}
}

// TestMagnetar_Sign_Ctx_MatchesPrecompileVerify is the FIPS 205
// counterpart: same shape, magnetar.sign_ctx → MAGS frame → raw
// FIPS 205 bytes → luxfi/crypto/slhdsa.PublicKey.VerifySignatureCtx.
// The verifier in luxfi/precompile/slhdsa/contract.go:264 calls the
// same primitive, so this is the on-chain SLH-DSA precompile
// surface minus calldata parsing.
//
// 1-of-1 keeps the test fast — the magnetar v0.5 primary primitive
// IS per-validator standalone, so threshold/participants is purely
// a session-cardinality knob (TestMagnetarRoundTrip uses the same
// shape).
func TestMagnetar_Sign_Ctx_MatchesPrecompileVerify(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()

	var kg keygenResult
	rpcCall(t, url, "magnetar.keygen", map[string]any{
		"threshold":    1,
		"participants": 1,
	}, &kg)
	if kg.PublicKey == "" {
		t.Fatal("magnetar.keygen: empty publicKey")
	}

	msg := []byte("magnetar sign_ctx -> precompile.VerifyCtx accept")
	msgHex := hex.EncodeToString(msg)
	ctxHex := hex.EncodeToString(precompileCtxSLHDSA)

	sigHex := signCtxRPCCall(t, url, "magnetar", msgHex, kg.PublicKey, ctxHex)

	// Strip MAGG / MAGS frames.
	gkBytes, err := hex.DecodeString(kg.PublicKey)
	if err != nil {
		t.Fatalf("decode pubKey hex: %v", err)
	}
	pub, err := magnetar.UnmarshalGroupKey(gkBytes)
	if err != nil {
		t.Fatalf("MAGG UnmarshalGroupKey: %v", err)
	}
	sigFrameBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode sig hex: %v", err)
	}
	var sig magnetar.Signature
	if err := sig.UnmarshalBinary(sigFrameBytes); err != nil {
		t.Fatalf("MAGS UnmarshalBinary: %v", err)
	}

	// The magnetar dispatcher ALWAYS runs ModeM192s (see magnetar.go:
	// magnetar.MustParamsFor(magnetar.ModeM192s) in Keygen). Map to
	// the equivalent luxfi/crypto/slhdsa mode. M192s = SHAKE-192s.
	if pub.Mode != magnetar.ModeM192s {
		t.Fatalf("unexpected pubkey mode %v, want %v", pub.Mode, magnetar.ModeM192s)
	}

	luxPub, err := luxslhdsa.PublicKeyFromBytes(pub.Bytes, luxslhdsa.SHAKE_192s)
	if err != nil {
		t.Fatalf("luxslhdsa.PublicKeyFromBytes: %v", err)
	}

	// Accept: precompile ctx → byte(1)
	acceptOK := luxPub.VerifySignatureCtx(msg, sig.Bytes, precompileCtxSLHDSA)
	var acceptByte byte
	if acceptOK {
		acceptByte = 1
	}
	if acceptByte != byte(1) {
		t.Fatalf("precompile accept-byte = %d, want byte(1)", acceptByte)
	}

	// Reject 1: empty ctx → byte(0).
	rejectEmptyOK := luxPub.VerifySignatureCtx(msg, sig.Bytes, nil)
	var rejectEmptyByte byte
	if rejectEmptyOK {
		rejectEmptyByte = 1
	}
	if rejectEmptyByte != byte(0) {
		t.Fatalf("precompile empty-ctx reject-byte = %d, want byte(0) — ctx is NOT propagated", rejectEmptyByte)
	}

	// Reject 2: wrong ctx → byte(0).
	wrongCtx := []byte("lux-evm-precompile-wrong-v1")
	rejectWrongOK := luxPub.VerifySignatureCtx(msg, sig.Bytes, wrongCtx)
	var rejectWrongByte byte
	if rejectWrongOK {
		rejectWrongByte = 1
	}
	if rejectWrongByte != byte(0) {
		t.Fatalf("precompile wrong-ctx reject-byte = %d, want byte(0)", rejectWrongByte)
	}
}

// TestPulsar_Sign_Ctx_EmptyCtxMatchesPlainSign asserts that
// sign_ctx with an empty ctxHex parameter produces a signature that
// verifies under empty-ctx verify (i.e., behaves as a vanilla FIPS
// 204 sign). This pins the convenience semantics documented on
// signCtxParams.CtxHex.
func TestPulsar_Sign_Ctx_EmptyCtxMatchesPlainSign(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()

	var kg keygenResult
	rpcCall(t, url, "pulsar.keygen", map[string]any{
		"threshold":    2,
		"participants": 3,
	}, &kg)

	msg := []byte("pulsar sign_ctx empty-ctx parity")
	msgHex := hex.EncodeToString(msg)
	sigHex := signCtxRPCCall(t, url, "pulsar", msgHex, kg.PublicKey, "")

	// Empty-ctx sign_ctx must verify under the stateless pubKey-only
	// VerifyBytes (which uses empty ctx internally).
	var vr verifyResult
	rpcCall(t, url, "pulsar.verify", map[string]any{
		"messageHex":   msgHex,
		"signatureHex": sigHex,
		"pubKeyHex":    kg.PublicKey,
	}, &vr)
	if !vr.OK {
		t.Fatal("empty-ctx sign_ctx output failed stateless empty-ctx verify")
	}
}

// TestMagnetar_Sign_Ctx_EmptyCtxMatchesPlainSign is the magnetar
// counterpart of the empty-ctx parity test above.
func TestMagnetar_Sign_Ctx_EmptyCtxMatchesPlainSign(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()

	var kg keygenResult
	rpcCall(t, url, "magnetar.keygen", map[string]any{
		"threshold":    1,
		"participants": 1,
	}, &kg)

	msg := []byte("magnetar sign_ctx empty-ctx parity")
	msgHex := hex.EncodeToString(msg)
	sigHex := signCtxRPCCall(t, url, "magnetar", msgHex, kg.PublicKey, "")

	var vr verifyResult
	rpcCall(t, url, "magnetar.verify", map[string]any{
		"messageHex":   msgHex,
		"signatureHex": sigHex,
		"pubKeyHex":    kg.PublicKey,
	}, &vr)
	if !vr.OK {
		t.Fatal("empty-ctx sign_ctx output failed stateless empty-ctx verify")
	}
}

// TestSign_Ctx_UnsupportedSchemeReturnsMethodNotFound asserts that
// schemes that do NOT implement ctxSigner surface a -32601 (method
// not found) JSON-RPC error rather than silently routing to a
// non-existent handler.
func TestSign_Ctx_UnsupportedSchemeReturnsMethodNotFound(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()

	for _, scheme := range []string{"cggmp21", "frost", "bls", "corona", "doerner"} {
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": scheme + ".sign_ctx",
			"params": map[string]any{
				"messageHex": "00",
				"pubKeyHex":  "00",
				"ctxHex":     "00",
			},
		})
		resp, err := http.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s: post: %v", scheme, err)
		}
		var env struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&env)
		resp.Body.Close()
		if env.Error == nil || env.Error.Code != -32601 {
			t.Fatalf("%s.sign_ctx: expected -32601, got %+v", scheme, env.Error)
		}
	}
}
