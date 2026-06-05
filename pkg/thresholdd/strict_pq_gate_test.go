// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// strict_pq_gate_test.go — race-clean tests for profile.go and the
// ZAP dispatcher's strict-PQ refusal behavior on Sign_Ctx.
//
// Coverage:
//
//   - TestRefuseUnderStrictPQ_PolicyMatrix walks every input the gate
//     function accepts and asserts the return value.
//   - TestSignCtx_StrictPQ_RejectsDealerShortcut drives a full ZAP
//     round trip; the dispatcher MUST surface ErrRefusedUnderStrictPQ
//     when the chain is on strict-PQ.
//   - TestSignCtx_LegacyCompatProfile_AllowsDealerShortcut proves the
//     same dispatcher with a legacy-compat chain returns a normal
//     signature.
//   - TestSignCtx_DispatcherDeclaresProfile demonstrates the chain
//     profile is reachable via the ChainID request field. Race-clean
//     via concurrent invocations.
//
// All tests run with t.Parallel() and -race.

// fakeChainResolver is a tiny test resolver with explicit per-chain
// profile mappings. Defaults to ProfileUnknown so unmapped chain IDs
// fail-OPEN (matches the documented behaviour).
type fakeChainResolver struct {
	mu       sync.RWMutex
	mapping  map[string]Profile
	queryCnt atomic.Int64
}

func newFakeChainResolver(mapping map[string]Profile) *fakeChainResolver {
	cp := make(map[string]Profile, len(mapping))
	for k, v := range mapping {
		cp[k] = v
	}
	return &fakeChainResolver{mapping: cp}
}

func (r *fakeChainResolver) ResolveChainProfile(chainID string) Profile {
	r.queryCnt.Add(1)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.mapping[chainID]; ok {
		return p
	}
	return ProfileUnknown
}

// TestRefuseUnderStrictPQ_PolicyMatrix walks the gate's input space
// directly (no dispatcher in the loop).
func TestRefuseUnderStrictPQ_PolicyMatrix(t *testing.T) {
	t.Parallel()

	strictResolver := newFakeChainResolver(map[string]Profile{
		"lux-mainnet": ProfileStrictPQ,
		"lux-testnet": ProfileLegacyCompat,
	})

	tests := []struct {
		name      string
		chainID   string
		resolver  ChainProfileResolver
		wantError bool
	}{
		{
			name:      "nil resolver passes (fail-OPEN)",
			chainID:   "lux-mainnet",
			resolver:  nil,
			wantError: false,
		},
		{
			name:      "empty chainID passes (no chain asserted)",
			chainID:   "",
			resolver:  strictResolver,
			wantError: false,
		},
		{
			name:      "strict-PQ chain refuses",
			chainID:   "lux-mainnet",
			resolver:  strictResolver,
			wantError: true,
		},
		{
			name:      "legacy-compat chain passes",
			chainID:   "lux-testnet",
			resolver:  strictResolver,
			wantError: false,
		},
		{
			name:      "unknown chain passes (fail-OPEN)",
			chainID:   "some-other-chain",
			resolver:  strictResolver,
			wantError: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := RefuseUnderStrictPQ(tc.chainID, "pulsar.sign_ctx", tc.resolver)
			if tc.wantError {
				if err == nil {
					t.Fatalf("RefuseUnderStrictPQ: expected error, got nil")
				}
				if !errors.Is(err, ErrRefusedUnderStrictPQ) {
					t.Fatalf("RefuseUnderStrictPQ: error %v does not wrap ErrRefusedUnderStrictPQ", err)
				}
			} else {
				if err != nil {
					t.Fatalf("RefuseUnderStrictPQ: unexpected error %v", err)
				}
			}
		})
	}
}

// TestIsStrictPQProfile_Direct mirrors the matrix above for the
// helper. Cheap parity check that IsStrictPQProfile and
// RefuseUnderStrictPQ agree on what "strict-PQ" means.
func TestIsStrictPQProfile_Direct(t *testing.T) {
	t.Parallel()

	resolver := newFakeChainResolver(map[string]Profile{
		"lux-mainnet": ProfileStrictPQ,
		"lux-testnet": ProfileLegacyCompat,
	})

	if !IsStrictPQProfile("lux-mainnet", resolver) {
		t.Fatalf("IsStrictPQProfile(lux-mainnet) = false, want true")
	}
	if IsStrictPQProfile("lux-testnet", resolver) {
		t.Fatalf("IsStrictPQProfile(lux-testnet) = true, want false")
	}
	if IsStrictPQProfile("unknown", resolver) {
		t.Fatalf("IsStrictPQProfile(unknown) = true, want false (fail-OPEN)")
	}
	if IsStrictPQProfile("anything", nil) {
		t.Fatalf("IsStrictPQProfile(_, nil) = true, want false (no resolver)")
	}
}

// startTestServerWithResolver brings up the ZAP dispatcher with the
// supplied chain-profile resolver. Returns the server pointer so
// tests can swap the resolver mid-run if they need to.
func startTestServerWithResolver(t *testing.T, resolver ChainProfileResolver) (*ZapServer, string, func()) {
	t.Helper()
	port := allocPort(t)
	srv, err := NewZapServer(ZapServerConfig{
		NodeID: "thresholdd-test-resolver",
		Port:   port,
	})
	if err != nil {
		t.Fatalf("NewZapServer: %v", err)
	}
	srv.SetChainProfileResolver(resolver)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	addr := "127.0.0.1:" + itoa(port)
	return srv, addr, srv.Stop
}

// itoa is a tiny strconv.Itoa avoiding the extra import burden in
// the test file (which already pulls a lot).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 6)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

// TestSignCtx_StrictPQ_RejectsDealerShortcut drives a full keygen +
// Sign_Ctx round trip against a strict-PQ-mapped chain ID. The
// dispatcher MUST return an error wrapping ErrRefusedUnderStrictPQ.
//
// Tests BOTH schemes (pulsar and magnetar) — the gate composes the
// same way on each, so any divergence in behavior is a bug.
func TestSignCtx_StrictPQ_RejectsDealerShortcut(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping strict-PQ dispatcher round-trip under -short")
	}

	type schemeCase struct {
		name  string
		t, n  int
		msg   string
		ctxIn string
	}
	cases := []schemeCase{
		{"pulsar", 2, 3, "pulsar strict-pq reject", "lux-evm-precompile-mldsa-v1"},
		{"magnetar", 1, 1, "magnetar strict-pq reject", "lux-evm-precompile-slhdsa-v1"},
	}

	for _, cse := range cases {
		cse := cse
		t.Run(cse.name, func(t *testing.T) {
			t.Parallel()
			resolver := newFakeChainResolver(map[string]Profile{
				"lux-mainnet": ProfileStrictPQ,
			})
			_, addr, stop := startTestServerWithResolver(t, resolver)
			defer stop()

			ctx := context.Background()
			c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
			if err != nil {
				t.Fatalf("ConnectZap: %v", err)
			}
			defer c.Close()

			pubKey, _, err := c.Keygen(ctx, cse.name, cse.t, cse.n)
			if err != nil {
				t.Fatalf("%s.keygen: %v", cse.name, err)
			}
			if len(pubKey) == 0 {
				t.Fatalf("%s.keygen: empty publicKey", cse.name)
			}

			// Sign_Ctx with chainID = "lux-mainnet" (strict-PQ) —
			// MUST refuse with the documented sentinel.
			_, err = c.SignCtx(ctx, cse.name, []byte(cse.msg), pubKey, []byte(cse.ctxIn), "lux-mainnet")
			if err == nil {
				t.Fatalf("%s strict-PQ refusal: expected error, got nil", cse.name)
			}
			if !errors.Is(err, ErrRefusedUnderStrictPQ) {
				t.Fatalf("%s strict-PQ refusal: error %v does not wrap ErrRefusedUnderStrictPQ", cse.name, err)
			}
		})
	}
}

// TestSignCtx_LegacyCompatProfile_AllowsDealerShortcut proves the
// SAME dispatcher with the SAME schemes returns a normal signature
// when the chain is mapped to legacy-compat. Catches a regression
// where the gate accidentally trips on every request.
func TestSignCtx_LegacyCompatProfile_AllowsDealerShortcut(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping legacy-compat dispatcher round-trip under -short")
	}

	type schemeCase struct {
		name  string
		t, n  int
		msg   string
		ctxIn string
	}
	cases := []schemeCase{
		{"pulsar", 2, 3, "pulsar legacy-compat allow", "lux-evm-precompile-mldsa-v1"},
		{"magnetar", 1, 1, "magnetar legacy-compat allow", "lux-evm-precompile-slhdsa-v1"},
	}

	for _, cse := range cases {
		cse := cse
		t.Run(cse.name, func(t *testing.T) {
			t.Parallel()
			resolver := newFakeChainResolver(map[string]Profile{
				"lux-testnet": ProfileLegacyCompat,
			})
			_, addr, stop := startTestServerWithResolver(t, resolver)
			defer stop()

			ctx := context.Background()
			c, err := ConnectZap(ctx, addr, WithZapCallTimeout(20*time.Minute))
			if err != nil {
				t.Fatalf("ConnectZap: %v", err)
			}
			defer c.Close()

			pubKey, _, err := c.Keygen(ctx, cse.name, cse.t, cse.n)
			if err != nil {
				t.Fatalf("%s.keygen: %v", cse.name, err)
			}

			sig, err := c.SignCtx(ctx, cse.name, []byte(cse.msg), pubKey, []byte(cse.ctxIn), "lux-testnet")
			if err != nil {
				t.Fatalf("%s legacy-compat: %v", cse.name, err)
			}
			if len(sig) == 0 {
				t.Fatalf("%s legacy-compat: empty signature", cse.name)
			}
		})
	}
}

// TestSignCtx_DispatcherDeclaresProfile proves the chain profile is
// reachable via the ChainID request field, and the gate trips
// identically on each chain. Race-cleanliness is exercised by
// TestSignCtx_DispatcherDeclaresProfile_Race below.
func TestSignCtx_DispatcherDeclaresProfile(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping dispatcher-declares-profile under -short (drives pulsar keygen)")
	}

	resolver := newFakeChainResolver(map[string]Profile{
		"strict-chain": ProfileStrictPQ,
		"compat-chain": ProfileLegacyCompat,
	})
	_, addr, stop := startTestServerWithResolver(t, resolver)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(60*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "pulsar", 2, 3)
	if err != nil {
		t.Fatalf("pulsar.keygen: %v", err)
	}

	msg := []byte("dispatcher-declares-profile")
	ctxIn := []byte("lux-evm-precompile-mldsa-v1")

	tests := []struct {
		name        string
		chainID     string
		wantRefused bool
	}{
		{"strict refuses", "strict-chain", true},
		{"compat allows", "compat-chain", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.SignCtx(ctx, "pulsar", msg, pubKey, ctxIn, tc.chainID)
			if tc.wantRefused {
				if err == nil {
					t.Fatalf("%s: expected refusal, got nil error", tc.name)
				}
				if !errors.Is(err, ErrRefusedUnderStrictPQ) {
					t.Fatalf("%s: error %v does not wrap ErrRefusedUnderStrictPQ", tc.name, err)
				}
			} else {
				if err != nil {
					t.Fatalf("%s: expected success, got error %v", tc.name, err)
				}
			}
		})
	}
}

// TestSignCtx_DispatcherDeclaresProfile_Race exercises the gate
// from many concurrent goroutines so any data race on the
// resolver, the server's chainProfileResolver field, or the
// per-request chain-ID plumbing is caught under `go test -race`.
func TestSignCtx_DispatcherDeclaresProfile_Race(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping dispatcher-declares-profile race test under -short (drives pulsar keygen)")
	}

	resolver := newFakeChainResolver(map[string]Profile{
		"strict-chain": ProfileStrictPQ,
		"compat-chain": ProfileLegacyCompat,
	})
	_, addr, stop := startTestServerWithResolver(t, resolver)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(60*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "pulsar", 2, 3)
	if err != nil {
		t.Fatalf("pulsar.keygen: %v", err)
	}

	msg := []byte("dispatcher-race")
	ctxIn := []byte("lux-evm-precompile-mldsa-v1")

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			// Alternate strict and compat chains so workers race
			// on different profile paths.
			chain := "strict-chain"
			wantRefused := true
			if idx%2 == 0 {
				chain = "compat-chain"
				wantRefused = false
			}
			_, err := c.SignCtx(ctx, "pulsar", msg, pubKey, ctxIn, chain)
			if wantRefused {
				if err == nil || !errors.Is(err, ErrRefusedUnderStrictPQ) {
					errCh <- errors.New("worker " + chain + ": expected ErrRefusedUnderStrictPQ")
				}
			} else {
				if err != nil {
					errCh <- errors.New("worker " + chain + ": unexpected error")
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("%v", err)
	}
}

// TestSignCtx_NoResolverWired_FailsOpen ensures that the default
// dispatcher (no SetChainProfileResolver call) does NOT refuse on a
// "lux-mainnet" chain ID.
func TestSignCtx_NoResolverWired_FailsOpen(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping no-resolver fail-OPEN test under -short (drives pulsar keygen)")
	}

	addr, stop := startTestServer(t)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(60*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "pulsar", 2, 3)
	if err != nil {
		t.Fatalf("pulsar.keygen: %v", err)
	}
	// "lux-mainnet" would refuse if a strict-PQ resolver were wired.
	_, err = c.SignCtx(ctx, "pulsar", []byte("no-resolver-wired"), pubKey,
		[]byte("lux-evm-precompile-mldsa-v1"), "lux-mainnet")
	if err != nil {
		t.Fatalf("no-resolver fail-OPEN broken: %v", err)
	}
}

// TestSignCtx_NoChainID_FailsOpen ensures that omitting the chain
// ID entirely lets the dispatcher fall through to the legacy path
// even when a strict-PQ resolver is wired.
func TestSignCtx_NoChainID_FailsOpen(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping empty-chainID fail-OPEN test under -short (drives pulsar keygen)")
	}

	resolver := newFakeChainResolver(map[string]Profile{
		"lux-mainnet": ProfileStrictPQ,
	})
	_, addr, stop := startTestServerWithResolver(t, resolver)
	defer stop()

	ctx := context.Background()
	c, err := ConnectZap(ctx, addr, WithZapCallTimeout(60*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, _, err := c.Keygen(ctx, "pulsar", 2, 3)
	if err != nil {
		t.Fatalf("pulsar.keygen: %v", err)
	}
	// Empty chainID → gate falls through.
	_, err = c.SignCtx(ctx, "pulsar", []byte("no-chain-id"), pubKey,
		[]byte("lux-evm-precompile-mldsa-v1"), "")
	if err != nil {
		t.Fatalf("empty chainID fail-OPEN broken: %v", err)
	}
}

// TestNewStaticChainProfileResolver_DefaultBehaviour exercises the
// static resolver constructor.
func TestNewStaticChainProfileResolver_DefaultBehaviour(t *testing.T) {
	t.Parallel()
	r := NewStaticChainProfileResolver(ProfileLegacyCompat, map[string]Profile{
		"strict": ProfileStrictPQ,
		"unset":  ProfileUnknown,
	})
	if got := r.ResolveChainProfile("strict"); got != ProfileStrictPQ {
		t.Fatalf("strict: got %s want strict-PQ", got)
	}
	if got := r.ResolveChainProfile("unset"); got != ProfileUnknown {
		t.Fatalf("unset: got %s want unknown", got)
	}
	if got := r.ResolveChainProfile("absent"); got != ProfileLegacyCompat {
		t.Fatalf("absent: got %s want legacy-compat (default)", got)
	}
}
