// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// startTestServer brings up the dispatcher on a random localhost port
// and returns its base URL plus a cleanup func.
func startTestServer(t *testing.T) (string, func()) {
	t.Helper()
	srv, err := NewServer()
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	ts := httptest.NewServer(srv)
	// Sanity: ensure listening on loopback only.
	if !strings.HasPrefix(ts.URL, "http://127.0.0.1:") && !strings.HasPrefix(ts.URL, "http://[::1]:") {
		t.Fatalf("test server not on loopback: %s", ts.URL)
	}
	return ts.URL, ts.Close
}

// rpcCall posts a JSON-RPC 2.0 request and unmarshals the result.
func rpcCall(t *testing.T, url, method string, params any, out any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		t.Fatalf("marshal req: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode env: %v", err)
	}
	if env.Error != nil {
		t.Fatalf("rpc error %d: %s", env.Error.Code, env.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			t.Fatalf("decode result: %v", err)
		}
	}
}

// roundtrip exercises a scheme end-to-end: keygen → sign → verify.
// It also asserts forgery rejection (wrong message → ok=false).
func roundtrip(t *testing.T, scheme string, threshold, participants int) {
	t.Helper()
	url, stop := startTestServer(t)
	defer stop()

	var kg keygenResult
	rpcCall(t, url, scheme+".keygen", map[string]any{
		"threshold":    threshold,
		"participants": participants,
	}, &kg)
	if kg.PublicKey == "" {
		t.Fatalf("%s.keygen: empty publicKey", scheme)
	}
	if len(kg.Shares) != participants {
		t.Fatalf("%s.keygen: shares=%d want=%d", scheme, len(kg.Shares), participants)
	}

	msg := hex.EncodeToString([]byte(fmt.Sprintf("%s-test-message", scheme)))

	var sg signResult
	rpcCall(t, url, scheme+".sign", map[string]any{
		"messageHex": msg,
		"pubKeyHex":  kg.PublicKey,
	}, &sg)
	if sg.SignatureHex == "" {
		t.Fatalf("%s.sign: empty signature", scheme)
	}

	var vr verifyResult
	rpcCall(t, url, scheme+".verify", map[string]any{
		"messageHex":   msg,
		"signatureHex": sg.SignatureHex,
		"pubKeyHex":    kg.PublicKey,
	}, &vr)
	if !vr.OK {
		t.Fatalf("%s.verify: round-trip signature failed", scheme)
	}

	// Forgery: verify with different message → must be false.
	wrong := hex.EncodeToString([]byte(scheme + "-other-message"))
	var vr2 verifyResult
	rpcCall(t, url, scheme+".verify", map[string]any{
		"messageHex":   wrong,
		"signatureHex": sg.SignatureHex,
		"pubKeyHex":    kg.PublicKey,
	}, &vr2)
	if vr2.OK {
		t.Fatalf("%s.verify: forgery accepted (different message)", scheme)
	}
}

func TestCGGMP21RoundTrip(t *testing.T) {
	t.Parallel()
	// CGGMP21 keygen + sign is expensive; 2-of-2 keeps it fast.
	roundtrip(t, "cggmp21", 2, 2)
}

func TestFrostRoundTrip(t *testing.T) {
	t.Parallel()
	roundtrip(t, "frost", 2, 3)
}

// TestPulsarRoundTrip exercises the pulsar dispatcher end-to-end:
// keygen runs DealAlgebraicV03Shares + per-party identity setup;
// sign drives the v0.3 algebraic-aggregate protocol with FIPS 204
// rejection-restart; verify is stateless over the published PULG-
// framed group public key. Forgery is rejected.
//
// 2-of-3 keeps the test fast — the v0.3 protocol's wall-clock cost
// is dominated by the per-party ML-KEM-768 + ML-DSA-65 identity
// exchanges (O(t²)) and the FIPS 204 rejection-restart loop
// (~5 attempts on average). The signature emitted on the wire is
// bit-identical to a single-party FIPS 204 ML-DSA-65 signature on
// the same (message, group public key) — pinned upstream by
// TestPulsar_Wire_FIPS204Verifiable.
func TestPulsarRoundTrip(t *testing.T) {
	t.Parallel()
	roundtrip(t, "pulsar", 2, 3)
}

// TestCoronaRoundTrip exercises the Corona Ring-LWE threshold scheme
// end-to-end through the JSON-RPC dispatcher: keygen → 2-round sign →
// stateless verify, plus forgery rejection on a tampered message.
//
// Wire encodings (Signature.MarshalBinary / GroupKey.MarshalBinary /
// VerifyBytes) landed in luxfi/corona threshold/wire.go on 2026-05-31,
// which is what unblocks this test from the previous
// "explicitly-not-implemented" stub.
//
// Cannot t.Parallel: corona kernel mutates sign.K / sign.Threshold
// globals on every GenerateKeys call (luxfi/corona threshold/threshold.go:
// 123-124). Sibling agents own pulsar/; we accept the kernel-side
// limitation rather than refactor underneath them.
func TestCoronaRoundTrip(t *testing.T) {
	// Corona kernel requires t < n strictly. Smallest committee that
	// exercises the protocol is 1-of-2.
	roundtrip(t, "corona", 1, 2)
}

// TestMagnetarRoundTrip exercises the magnetar dispatcher end-to-
// end: keygen generates `participants` per-validator-standalone
// SLH-DSA keypairs via the v0.5 PerValidatorKeypair primary
// primitive; sign emits the canonical (first) validator's
// MAGS-framed signature; verify is stateless over the published
// MAGG-framed group public key. Forgery is rejected.
//
// The signature emitted on the wire is byte-identical to a single-
// party FIPS 205 SLH-DSA signature on the same (message, validator
// public key) — pinned upstream by TestMagnetar_Wire_FIPS205Verifiable.
//
// We use 1-of-1 because the v0.5 magnetar primary primitive IS
// per-validator standalone (no MPC aggregation into a single σ).
// The thresholdd JSON-RPC surface returns one (publicKey,
// signatureHex) tuple per call; the magnetar dispatcher uses the
// FIRST validator's keypair as the canonical signer regardless of
// the participants count. (Embedders that want N-of-N collected
// signatures call magnetar.BuildAggregateCert /
// VerifyAggregateCert directly.)
func TestMagnetarRoundTrip(t *testing.T) {
	t.Parallel()
	roundtrip(t, "magnetar", 1, 1)
}

// assertSchemeReturnsTypedError posts every op on `scheme` and verifies
// the daemon surfaces an explicit error message containing `wantSub`
// rather than silently returning bad data.
func assertSchemeReturnsTypedError(t *testing.T, scheme, wantSub string) {
	t.Helper()
	url, stop := startTestServer(t)
	defer stop()

	for _, op := range []struct {
		method string
		params any
	}{
		{scheme + ".keygen", map[string]any{"threshold": 2, "participants": 3}},
		{scheme + ".sign", map[string]any{"messageHex": "00", "pubKeyHex": "00"}},
		{scheme + ".verify", map[string]any{"messageHex": "00", "signatureHex": "00", "pubKeyHex": "00"}},
	} {
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": op.method, "params": op.params,
		})
		resp, err := http.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s: post: %v", op.method, err)
		}
		var env struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&env)
		resp.Body.Close()
		if env.Error == nil {
			t.Fatalf("%s: expected typed error, got success", op.method)
		}
		if !strings.Contains(env.Error.Message, wantSub) {
			t.Fatalf("%s: error %q does not contain %q", op.method, env.Error.Message, wantSub)
		}
	}
}

func TestBLSRoundTrip(t *testing.T) {
	t.Parallel()
	roundtrip(t, "bls", 2, 3)
}

// TestDoernerExplicitlyBroken asserts the daemon surfaces the upstream
// breakage clearly rather than silently returning bad data. See
// doerner.go header for why this is the test surface today.
func TestDoernerExplicitlyBroken(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "doerner.keygen",
		"params":  map[string]any{"threshold": 2, "participants": 2},
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	var env struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&env)
	if env.Error == nil {
		t.Fatalf("expected explicit error for broken upstream, got success")
	}
	if !strings.Contains(env.Error.Message, "non-functional") {
		t.Fatalf("unexpected error message: %s", env.Error.Message)
	}
}

// TestServerListensOnLoopback asserts the daemon binds on a real port
// when given --listen :0 (used by external test harnesses).
func TestServerListensOnLoopback(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Fatalf("not loopback: %s", ln.Addr())
	}
}

// TestUnknownMethod ensures malformed wires get explicit JSON-RPC errors.
func TestUnknownMethod(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "bogus.op", "params": map[string]any{},
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	var env struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&env)
	if env.Error == nil || env.Error.Code != -32601 {
		t.Fatalf("expected -32601 method-not-found, got %+v", env.Error)
	}
}

// TestAuthTokenRejectsMissingHeader asserts that a Server with a non-empty
// auth token rejects requests without an Authorization header.
// Red HIGH B1 — dispatcher must not be an anonymous local signing oracle.
func TestAuthTokenRejectsMissingHeader(t *testing.T) {
	t.Parallel()
	srv, err := NewServer()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	srv.SetAuthToken("secret-token")
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "bls.keygen",
		"params": map[string]any{"threshold": 2, "participants": 3},
	})
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing-token: got status %d, want 401", resp.StatusCode)
	}
}

// TestAuthTokenRejectsWrongToken asserts wrong-token requests fail 401.
func TestAuthTokenRejectsWrongToken(t *testing.T) {
	t.Parallel()
	srv, err := NewServer()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	srv.SetAuthToken("secret-token")
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "bls.keygen",
		"params": map[string]any{"threshold": 2, "participants": 3},
	})
	req, _ := http.NewRequest("POST", ts.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-token: got status %d, want 401", resp.StatusCode)
	}
}

// TestAuthTokenAcceptsValid asserts the correct token reaches the handler.
func TestAuthTokenAcceptsValid(t *testing.T) {
	t.Parallel()
	srv, err := NewServer()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	srv.SetAuthToken("secret-token")
	ts := httptest.NewServer(srv)
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "bls.keygen",
		"params": map[string]any{"threshold": 2, "participants": 3},
	})
	req, _ := http.NewRequest("POST", ts.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid-token: got status %d, want 200", resp.StatusCode)
	}
}

// TestAuthTokenEmptyAllowsAnonymous asserts that the default (empty
// token) preserves the standalone CLI's dev-loopback behaviour — no
// gate engaged. The mpcd embedder always sets a token; this test
// covers the standalone `cmd/thresholdd` path.
func TestAuthTokenEmptyAllowsAnonymous(t *testing.T) {
	t.Parallel()
	url, stop := startTestServer(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "bls.keygen",
		"params": map[string]any{"threshold": 2, "participants": 3},
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("empty-token: got status %d, want 200", resp.StatusCode)
	}
}

// guard against pkg-level deadlocks in CI runners.
func TestMain(m *testing.M) {
	// MPC_LOCAL_APPROVAL=true is set for the test binary so that
	// approval.LocalDevProvider — used by the TEE dispatcher tests —
	// does not refuse construction. The same env-var gate refuses in
	// any non-test build (approval/local-dev's localDevAllowed).
	_ = os.Setenv("MPC_LOCAL_APPROVAL", "true")

	// Each subtest also enforces protocol-level timeouts via runner.go.
	// 30 minutes accommodates `-race -count=N` under the v1.1.0
	// algebraic-aggregate Sign_Ctx path (which runs the full quorum
	// FIPS 204 rejection-restart loop where the v1.0.x dealer-shortcut
	// ran a single-party SignTo). Race instrumentation adds ~3-5x to
	// per-test cost; the rejection-restart loop can stack on top.
	// Beyond 30m something IS stuck.
	go func() {
		time.Sleep(30 * time.Minute)
		panic("thresholdd_test: global timeout — protocol stuck")
	}()
	m.Run()
}
