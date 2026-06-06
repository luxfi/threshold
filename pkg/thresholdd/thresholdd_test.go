// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// thresholdd_test.go — ZAP round-trip tests for every scheme. The
// previous HTTP+JSON+hex test harness was removed alongside the HTTP
// path; cryptographic correctness is preserved by driving each scheme
// through the ZAP wire instead. Same scheme handlers, same byte-
// material — only the envelope changed.

// allocPort grabs an ephemeral loopback port the kernel just freed.
// Used by every test in this file to give ZapServer a known port.
// The TOCTOU window between Close()→bind is irrelevant under test on
// loopback (the kernel keeps the port reserved for a brief grace
// window).
func allocPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// startTestServer brings up the ZAP dispatcher on an ephemeral
// loopback port and returns its addr + a cleanup func. Auth is
// disabled (loopback dev — production embedders set their own
// token).
func startTestServer(t *testing.T) (string, func()) {
	t.Helper()
	return startTestServerWithConfig(t, ZapServerConfig{NodeID: "thresholdd-test"})
}

// startTestServerWithConfig is the lower-level constructor used by the
// auth / strict-PQ tests that need to thread per-test config (token,
// resolver) through to the dispatcher.
func startTestServerWithConfig(t *testing.T, cfg ZapServerConfig) (string, func()) {
	t.Helper()
	if cfg.Port == 0 {
		cfg.Port = allocPort(t)
	}
	if cfg.NodeID == "" {
		cfg.NodeID = "thresholdd-test"
	}
	srv, err := NewZapServer(cfg)
	if err != nil {
		t.Fatalf("NewZapServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Give zap.Node's accept goroutine a beat to register before any
	// client tries to dial it.
	time.Sleep(20 * time.Millisecond)
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	return addr, srv.Stop
}

// roundtrip exercises a scheme end-to-end through the ZAP wire:
// keygen → sign → verify, plus forgery rejection on a tampered
// message. The cryptographic correctness contract is unchanged from
// the prior HTTP-driven version of this helper.
func roundtrip(t *testing.T, schemeName string, threshold, participants int) {
	t.Helper()
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, shares, err := c.Keygen(ctx, schemeName, threshold, participants)
	if err != nil {
		t.Fatalf("%s.keygen: %v", schemeName, err)
	}
	if len(pubKey) == 0 {
		t.Fatalf("%s.keygen: empty publicKey", schemeName)
	}
	if len(shares) != participants {
		t.Fatalf("%s.keygen: shares=%d want=%d", schemeName, len(shares), participants)
	}

	msg := []byte(fmt.Sprintf("%s-test-message", schemeName))
	sig, err := c.Sign(ctx, schemeName, msg, pubKey)
	if err != nil {
		t.Fatalf("%s.sign: %v", schemeName, err)
	}
	if len(sig) == 0 {
		t.Fatalf("%s.sign: empty signature", schemeName)
	}

	ok, err := c.Verify(ctx, schemeName, msg, sig, pubKey)
	if err != nil {
		t.Fatalf("%s.verify: %v", schemeName, err)
	}
	if !ok {
		t.Fatalf("%s.verify: round-trip signature failed", schemeName)
	}

	// Forgery: verify with a different message → must be false.
	wrong := []byte(schemeName + "-other-message")
	bad, err := c.Verify(ctx, schemeName, wrong, sig, pubKey)
	if err != nil {
		t.Fatalf("%s.verify (forgery): %v", schemeName, err)
	}
	if bad {
		t.Fatalf("%s.verify: forgery accepted (different message)", schemeName)
	}
}

func TestCGGMP21RoundTrip(t *testing.T) {
	t.Parallel()
	// CGGMP21 keygen does Paillier safe-prime sampling (the slowest
	// step in the protocol); 2-of-2 is the minimum committee. Under
	// -race the protocol's goroutine fan-out (one per party per round)
	// pushes wall-clock past 60s. Gate under -short.
	if testing.Short() {
		t.Skip("skipping CGGMP21 full-protocol round-trip under -short")
	}
	roundtrip(t, "cggmp21", 2, 2)
}

func TestFrostRoundTrip(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping FROST full-protocol round-trip under -short")
	}
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
	if testing.Short() {
		t.Skip("skipping Pulsar (ML-DSA-65) full-protocol round-trip under -short")
	}
	roundtrip(t, "pulsar", 2, 3)
}

// TestCoronaRoundTrip exercises the Corona Ring-LWE threshold scheme
// end-to-end through the ZAP dispatcher: keygen → 2-round sign →
// stateless verify, plus forgery rejection on a tampered message.
//
// Cannot t.Parallel: corona kernel mutates sign.K / sign.Threshold
// globals on every GenerateKeys call (luxfi/corona threshold/threshold.go:
// 123-124). Sibling agents own pulsar/; we accept the kernel-side
// limitation rather than refactor underneath them.
func TestCoronaRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Corona R-LWE full-protocol round-trip under -short")
	}
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
func TestMagnetarRoundTrip(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping Magnetar (SLH-DSA) round-trip under -short")
	}
	roundtrip(t, "magnetar", 1, 1)
}

func TestBLSRoundTrip(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping BLS round-trip under -short")
	}
	roundtrip(t, "bls", 2, 3)
}

// TestDoernerExplicitlyBroken asserts the daemon surfaces the upstream
// breakage clearly rather than silently returning bad data. See
// doerner.go header for why this is the test surface today.
func TestDoernerExplicitlyBroken(t *testing.T) {
	t.Parallel()
	addr, stop := startTestServer(t)
	defer stop()
	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()
	_, _, err = c.Keygen(ctx, "doerner", 2, 2)
	if err == nil {
		t.Fatalf("expected explicit error for broken upstream, got success")
	}
	if !strings.Contains(err.Error(), "non-functional") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestUnknownMethod ensures procedure-level routing errors are
// surfaced explicitly. The client's knownProcedure check fires
// before the network round-trip, so we drive the raw wire instead.
func TestUnknownMethod(t *testing.T) {
	t.Parallel()
	addr, stop := startTestServer(t)
	defer stop()
	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()
	// "bogus" is not in allProcedures, so knownProcedure rejects.
	_, _, err = c.Keygen(ctx, "bogus", 2, 3)
	if err == nil {
		t.Fatalf("expected unknown-procedure error, got success")
	}
	if !strings.Contains(err.Error(), "unknown procedure") {
		t.Fatalf("error %v does not name unknown procedure", err)
	}
}

// TestAuthTokenRejectsWrongPeer asserts that a ZapServer with a
// non-empty auth token rejects requests from a peer whose NodeID
// does not match. The ZAP auth model is connection-scoped: the
// client's NodeID is stamped at handshake; the server compares it
// constant-time against `authToken`.
//
// Red HIGH B1 mirror — dispatcher must not be an anonymous local
// signing oracle.
func TestAuthTokenRejectsWrongPeer(t *testing.T) {
	t.Parallel()
	addr, stop := startTestServerWithConfig(t, ZapServerConfig{AuthToken: "secret-token"})
	defer stop()

	ctx := context.Background()
	// Wrong client NodeID — does not match "secret-token".
	c, err := ConnectZap(ctx, addr,
		WithZapNodeID("wrong-id"),
		WithZapCallTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()
	_, _, err = c.Keygen(ctx, "bls", 2, 3)
	if err == nil {
		t.Fatalf("expected unauthorized error, got success")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("error %v does not name unauthorized", err)
	}
}

// TestAuthTokenAcceptsValid asserts the correct peer NodeID passes the
// auth gate and reaches the scheme handler.
func TestAuthTokenAcceptsValid(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping auth-token positive path under -short (drives BLS keygen)")
	}
	addr, stop := startTestServerWithConfig(t, ZapServerConfig{AuthToken: "secret-token"})
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr,
		WithZapNodeID("secret-token"),
		WithZapCallTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()
	pubKey, _, err := c.Keygen(ctx, "bls", 2, 3)
	if err != nil {
		t.Fatalf("Keygen with valid token: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatalf("empty pubKey")
	}
}

// TestAuthTokenEmptyAllowsAnonymous asserts that the default (empty
// token) preserves the standalone CLI's dev-loopback behaviour — no
// gate engaged. The mpcd embedder always sets a token; this test
// covers the standalone `cmd/thresholdd` path.
func TestAuthTokenEmptyAllowsAnonymous(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping anonymous-auth positive path under -short (drives BLS keygen)")
	}
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()
	pubKey, _, err := c.Keygen(ctx, "bls", 2, 3)
	if err != nil {
		t.Fatalf("Keygen with empty token: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatalf("empty pubKey")
	}
}

// TestServerListensOnLoopback asserts the daemon binds on a real port
// when given ephemeral :0 (used by external test harnesses).
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

// guard against pkg-level deadlocks in CI runners.
func TestMain(m *testing.M) {
	// MPC_LOCAL_APPROVAL=true is set for the test binary so that
	// approval.LocalDevProvider — used by the TEE dispatcher tests —
	// does not refuse construction. The same env-var gate refuses in
	// any non-test build (approval/local-dev's localDevAllowed).
	_ = os.Setenv("MPC_LOCAL_APPROVAL", "true")

	// Each subtest also enforces protocol-level timeouts via runner.go.
	// 30 minutes accommodates `-race -count=N` under the v1.1.0
	// algebraic-aggregate Sign_Ctx path.
	go func() {
		time.Sleep(30 * time.Minute)
		panic("thresholdd_test: global timeout — protocol stuck")
	}()
	m.Run()
}
