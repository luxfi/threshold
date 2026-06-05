// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// server_test.go — ZAP-side correctness + benchmark tests. The prior
// HTTP↔ZAP parity tests are gone with the HTTP path; cryptographic
// correctness across the ZAP wire is asserted by thresholdd_test.go
// (full per-scheme round-trips) and the dedicated tests here.

// TestZapServer_BLSRoundTrip exercises keygen + sign + verify end-
// to-end over the ZAP wire. BLS keygen is fast (no Paillier safe-
// prime sampling) so this is the cheapest smoke test.
func TestZapServer_BLSRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BLS round-trip under -short")
	}
	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, shares, err := c.Keygen(ctx, "bls", 2, 3)
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatalf("empty pubKey")
	}
	if len(shares) != 3 {
		t.Fatalf("shares=%d want=3", len(shares))
	}

	msg := []byte("zap-bls-roundtrip-message")
	sig, err := c.Sign(ctx, "bls", msg, pubKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}

	ok, err := c.Verify(ctx, "bls", msg, sig, pubKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("Verify failed: round-trip signature rejected")
	}

	// Forgery: different message must verify false.
	wrong := []byte("zap-bls-other-message")
	bad, err := c.Verify(ctx, "bls", wrong, sig, pubKey)
	if err != nil {
		t.Fatalf("Verify (forgery): %v", err)
	}
	if bad {
		t.Fatalf("Verify accepted forgery")
	}
}

// TestZapShares_RoundTrip covers the EncodeShares / DecodeShares
// helper. Trivial layout, but a regression here would corrupt every
// keygen response, so pin it.
func TestZapShares_RoundTrip(t *testing.T) {
	cases := [][]string{
		nil,
		{},
		{"1"},
		{"1", "2", "3"},
		{"", "a", "bb", "ccc", "1234567890"},
		{"long-string-share-id-that-should-still-survive-the-round-trip"},
	}
	for i, in := range cases {
		buf := EncodeShares(in)
		out, err := DecodeShares(buf)
		if err != nil {
			t.Errorf("case %d: DecodeShares: %v", i, err)
			continue
		}
		if len(out) != len(in) {
			t.Errorf("case %d: len=%d want=%d", i, len(out), len(in))
			continue
		}
		for j := range in {
			if in[j] != out[j] {
				t.Errorf("case %d/%d: %q != %q", i, j, in[j], out[j])
			}
		}
	}
}

// TestZapShares_TruncatedBlob asserts the decoder refuses partial
// input rather than silently returning a partial list.
func TestZapShares_TruncatedBlob(t *testing.T) {
	buf := EncodeShares([]string{"a", "bc", "def"})
	for cut := 1; cut < len(buf); cut++ {
		_, err := DecodeShares(buf[:cut])
		if err == nil {
			t.Errorf("cut=%d: expected error on truncated input", cut)
		}
	}
}

// TestProcOpcode_StableAndNonReserved spot-checks the FNV-1a opcode
// derivation. The procedure set is small + fixed; collisions here
// would route the wrong handler.
func TestProcOpcode_StableAndNonReserved(t *testing.T) {
	seen := make(map[uint16]string)
	for _, p := range allProcedures {
		op := procOpcode(p.name)
		// upper byte must be 1..254 (zapclient reserves 0 and 0xff)
		hi := byte(op >> 8)
		if hi == 0x00 || hi == 0xff {
			t.Errorf("proc %q hashes to reserved opcode 0x%04x", p.name, op)
		}
		if existing, dup := seen[op]; dup {
			t.Errorf("opcode collision: %q and %q both hash to 0x%04x — rename one", existing, p.name, op)
		}
		seen[op] = p.name
	}
}

// BenchmarkZapServer_BLSSign measures end-to-end Sign() latency over
// the ZAP transport. Reports ns/op + ops/sec.
func BenchmarkZapServer_BLSSign(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("probe listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	srv, err := NewZapServer(ZapServerConfig{NodeID: "bench-zap", Port: port})
	if err != nil {
		b.Fatalf("NewZapServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		b.Fatalf("Start: %v", err)
	}
	defer srv.Stop()
	time.Sleep(20 * time.Millisecond)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(30*time.Second))
	if err != nil {
		b.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "bls", 2, 3)
	if err != nil {
		b.Fatalf("Keygen: %v", err)
	}
	msg := []byte("bench-message-zap")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := c.Sign(ctx, "bls", msg, pubKey)
		if err != nil {
			b.Fatalf("Sign iter %d: %v", i, err)
		}
	}
}

// BenchmarkZapServer_BLSVerify measures end-to-end Verify() latency
// over the ZAP transport.
func BenchmarkZapServer_BLSVerify(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("probe: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	srv, err := NewZapServer(ZapServerConfig{NodeID: "bench-zap-v", Port: port})
	if err != nil {
		b.Fatalf("NewZapServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		b.Fatalf("Start: %v", err)
	}
	defer srv.Stop()
	time.Sleep(20 * time.Millisecond)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(30*time.Second))
	if err != nil {
		b.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "bls", 2, 3)
	if err != nil {
		b.Fatalf("Keygen: %v", err)
	}
	msg := []byte("bench-verify-msg")
	sig, err := c.Sign(ctx, "bls", msg, pubKey)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := c.Verify(ctx, "bls", msg, sig, pubKey)
		if err != nil {
			b.Fatalf("Verify iter %d: %v", i, err)
		}
		if !ok {
			b.Fatalf("Verify iter %d: rejected own signature", i)
		}
	}
}
