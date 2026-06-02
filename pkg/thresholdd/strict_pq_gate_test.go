// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// strict_pq_gate_test.go — race-clean tests for profile.go and the
// dispatcher's strict-PQ refusal behavior on Sign_Ctx.
//
// Coverage:
//
//   - TestRefuseUnderStrictPQ_PolicyMatrix walks every input the gate
//     function accepts and asserts the return value.
//   - TestSignCtx_StrictPQ_RejectsDealerShortcut drives a full RPC
//     round trip; the dispatcher MUST surface HTTP 503 + the
//     documented body when the chain is on strict-PQ.
//   - TestSignCtx_LegacyCompatProfile_AllowsDealerShortcut proves the
//     same dispatcher with a legacy-compat chain returns a normal
//     signature (HTTP 200 + signatureHex).
//   - TestSignCtx_DispatcherDeclaresProfile demonstrates the chain
//     profile is reachable via BOTH the JSON body ChainID field AND
//     the X-Chain-ID HTTP header. Race-clean via concurrent invocations.
//
// All tests run with t.Parallel() and -race.

// staticChainResolver is a tiny test resolver with explicit per-chain
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
// directly (no dispatcher in the loop). One row per documented
// branch — the gate is small enough that exhaustive coverage is
// cheap and prevents regressions when the body is edited.
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

// startTestServerWithResolver brings up the dispatcher with the
// supplied chain-profile resolver. The auth gate stays disabled
// for this test (loopback only — Server's auth token is for
// production embedders).
func startTestServerWithResolver(t *testing.T, resolver ChainProfileResolver) (*Server, string, func()) {
	t.Helper()
	srv, err := NewServer()
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	srv.SetChainProfileResolver(resolver)
	ts := httptest.NewServer(srv)
	if !strings.HasPrefix(ts.URL, "http://127.0.0.1:") && !strings.HasPrefix(ts.URL, "http://[::1]:") {
		t.Fatalf("test server not on loopback: %s", ts.URL)
	}
	return srv, ts.URL, ts.Close
}

// postSignCtx hits <scheme>.sign_ctx with the supplied chain ID
// (passed in both the JSON body and via X-Chain-ID header — body
// wins by contract). Returns the raw HTTP response so tests can
// assert status + body precisely.
func postSignCtx(t *testing.T, url, scheme, msgHex, pkHex, ctxHex, chainID string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": scheme + ".sign_ctx",
		"params": map[string]any{
			"messageHex": msgHex,
			"pubKeyHex":  pkHex,
			"ctxHex":     ctxHex,
			"chainID":    chainID,
		},
	})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if chainID != "" {
		req.Header.Set("X-Chain-ID", chainID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

// TestSignCtx_StrictPQ_RejectsDealerShortcut drives a full keygen +
// Sign_Ctx round trip against a strict-PQ-mapped chain ID. The
// dispatcher MUST return HTTP 503 + the documented body. This is
// the headline gate test — proves the strict-PQ refusal is
// load-bearing on the actual JSON-RPC surface, not just the unit
// function.
//
// Tests BOTH schemes (pulsar and magnetar) — the gate composes the
// same way on each, so any divergence in behavior is a bug.
//
// Each scheme runs in its own t.Run with its own server so the
// httptest cleanup order does not race with parallel subtests.
func TestSignCtx_StrictPQ_RejectsDealerShortcut(t *testing.T) {
	t.Parallel()

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

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			resolver := newFakeChainResolver(map[string]Profile{
				"lux-mainnet": ProfileStrictPQ,
			})
			_, url, stop := startTestServerWithResolver(t, resolver)
			defer stop()

			var kg keygenResult
			rpcCall(t, url, c.name+".keygen", map[string]any{
				"threshold":    c.t,
				"participants": c.n,
			}, &kg)
			if kg.PublicKey == "" {
				t.Fatalf("%s.keygen: empty publicKey", c.name)
			}

			// Sign_Ctx with chainID = "lux-mainnet" (strict-PQ) —
			// MUST refuse. HTTP 503 + documented body.
			resp := postSignCtx(t, url, c.name,
				hex.EncodeToString([]byte(c.msg)),
				kg.PublicKey,
				hex.EncodeToString([]byte(c.ctxIn)),
				"lux-mainnet")
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusServiceUnavailable {
				bodyBytes, _ := io.ReadAll(resp.Body)
				t.Fatalf("%s strict-PQ refusal: status=%d body=%s; want 503 + documented body",
					c.name, resp.StatusCode, string(bodyBytes))
			}
			gotBody, _ := io.ReadAll(resp.Body)
			if string(gotBody) != strictPQRefusalBody {
				t.Fatalf("%s strict-PQ refusal body=%q want=%q",
					c.name, string(gotBody), strictPQRefusalBody)
			}
		})
	}
}

// TestSignCtx_LegacyCompatProfile_AllowsDealerShortcut proves the
// SAME dispatcher with the SAME schemes returns a normal HTTP 200
// + signatureHex when the chain is mapped to legacy-compat. Catches
// a regression where the gate accidentally trips on every request.
//
// Each scheme gets its own server (subtests t.Parallel, parent
// defer fires after subtests complete only if the parent does
// NOT also parallelize — we side-step by per-subtest setup).
func TestSignCtx_LegacyCompatProfile_AllowsDealerShortcut(t *testing.T) {
	t.Parallel()

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

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			resolver := newFakeChainResolver(map[string]Profile{
				"lux-testnet": ProfileLegacyCompat,
			})
			_, url, stop := startTestServerWithResolver(t, resolver)
			defer stop()

			var kg keygenResult
			rpcCall(t, url, c.name+".keygen", map[string]any{
				"threshold":    c.t,
				"participants": c.n,
			}, &kg)

			resp := postSignCtx(t, url, c.name,
				hex.EncodeToString([]byte(c.msg)),
				kg.PublicKey,
				hex.EncodeToString([]byte(c.ctxIn)),
				"lux-testnet")
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("%s legacy-compat: status=%d body=%s; want 200 + signature",
					c.name, resp.StatusCode, string(body))
			}
			var env struct {
				Result *signResult `json:"result"`
				Error  *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
				t.Fatalf("decode env: %v", err)
			}
			if env.Error != nil {
				t.Fatalf("%s legacy-compat: rpc error %d: %s",
					c.name, env.Error.Code, env.Error.Message)
			}
			if env.Result == nil || env.Result.SignatureHex == "" {
				t.Fatalf("%s legacy-compat: empty signature", c.name)
			}
		})
	}
}

// TestSignCtx_DispatcherDeclaresProfile proves the chain profile
// is reachable via BOTH the JSON body ChainID field AND the
// X-Chain-ID HTTP header, and that the gate trips identically on
// each.
//
// The outer test holds the server + pre-keygen state; subtests
// run sequentially (no t.Parallel) so the shared server stays
// alive for every subtest. Race-cleanliness is exercised by
// TestSignCtx_DispatcherDeclaresProfile_Race below which drives
// the resolver from concurrent goroutines.
func TestSignCtx_DispatcherDeclaresProfile(t *testing.T) {
	t.Parallel()

	resolver := newFakeChainResolver(map[string]Profile{
		"strict-chain": ProfileStrictPQ,
		"compat-chain": ProfileLegacyCompat,
	})
	_, url, stop := startTestServerWithResolver(t, resolver)
	defer stop()

	// Pre-keygen one session (pulsar 2-of-3 is the canonical smoke
	// shape; the gate logic is identical for magnetar so testing
	// pulsar here is sufficient).
	var kg keygenResult
	rpcCall(t, url, "pulsar.keygen", map[string]any{
		"threshold":    2,
		"participants": 3,
	}, &kg)

	msg := hex.EncodeToString([]byte("dispatcher-declares-profile"))
	ctxHex := hex.EncodeToString([]byte("lux-evm-precompile-mldsa-v1"))

	tests := []struct {
		name       string
		chainID    string
		viaHeader  bool
		viaBody    bool
		wantStatus int
	}{
		{"strict via header only", "strict-chain", true, false, http.StatusServiceUnavailable},
		{"strict via body only", "strict-chain", false, true, http.StatusServiceUnavailable},
		{"strict via both header+body", "strict-chain", true, true, http.StatusServiceUnavailable},
		{"compat via header only", "compat-chain", true, false, http.StatusOK},
		{"compat via body only", "compat-chain", false, true, http.StatusOK},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "pulsar.sign_ctx",
				"params": map[string]any{
					"messageHex": msg,
					"pubKeyHex":  kg.PublicKey,
					"ctxHex":     ctxHex,
				},
			}
			if tc.viaBody {
				body["params"].(map[string]any)["chainID"] = tc.chainID
			}
			bs, _ := json.Marshal(body)
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bs))
			if err != nil {
				t.Fatalf("build req: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if tc.viaHeader {
				req.Header.Set("X-Chain-ID", tc.chainID)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				bs, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d body=%s; want %d", resp.StatusCode, string(bs), tc.wantStatus)
			}
		})
	}
}

// TestSignCtx_DispatcherDeclaresProfile_Race exercises the gate
// from many concurrent goroutines so any data race on the
// resolver, the server's chainProfileResolver field, or the
// per-request body+header plumbing is caught under `go test -race`.
func TestSignCtx_DispatcherDeclaresProfile_Race(t *testing.T) {
	t.Parallel()

	resolver := newFakeChainResolver(map[string]Profile{
		"strict-chain": ProfileStrictPQ,
		"compat-chain": ProfileLegacyCompat,
	})
	_, url, stop := startTestServerWithResolver(t, resolver)
	defer stop()

	var kg keygenResult
	rpcCall(t, url, "pulsar.keygen", map[string]any{
		"threshold":    2,
		"participants": 3,
	}, &kg)

	msg := hex.EncodeToString([]byte("dispatcher-race"))
	ctxHex := hex.EncodeToString([]byte("lux-evm-precompile-mldsa-v1"))

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
			wantStatus := http.StatusServiceUnavailable
			if idx%2 == 0 {
				chain = "compat-chain"
				wantStatus = http.StatusOK
			}
			resp := postSignCtx(t, url, "pulsar", msg, kg.PublicKey, ctxHex, chain)
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != wantStatus {
				errCh <- errors.New("worker " + chain + ": unexpected status")
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
// "lux-mainnet" chain ID. Documents the fail-OPEN behaviour: an
// embedder that forgets to wire a resolver gets the legacy
// behaviour, not a hard refusal. (Production embedders pair the
// outer admission gate with an explicit StaticChainProfileResolver
// default of ProfileStrictPQ if they want fail-CLOSED.)
func TestSignCtx_NoResolverWired_FailsOpen(t *testing.T) {
	t.Parallel()

	// Build server WITHOUT calling SetChainProfileResolver.
	srv, err := NewServer()
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	var kg keygenResult
	rpcCall(t, ts.URL, "pulsar.keygen", map[string]any{
		"threshold":    2,
		"participants": 3,
	}, &kg)

	resp := postSignCtx(t, ts.URL, "pulsar",
		hex.EncodeToString([]byte("no-resolver-wired")),
		kg.PublicKey,
		hex.EncodeToString([]byte("lux-evm-precompile-mldsa-v1")),
		"lux-mainnet") // would refuse if a strict-PQ resolver were wired
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(resp.Body)
		t.Fatalf("no-resolver fail-OPEN broken: status=%d body=%s; want 200",
			resp.StatusCode, string(bs))
	}
}

// TestSignCtx_NoChainID_FailsOpen ensures that omitting the chain
// ID entirely lets the dispatcher fall through to the legacy path
// even when a strict-PQ resolver is wired. Documents the
// "no chain asserted, no posture to enforce" branch of the gate.
func TestSignCtx_NoChainID_FailsOpen(t *testing.T) {
	t.Parallel()

	resolver := newFakeChainResolver(map[string]Profile{
		"lux-mainnet": ProfileStrictPQ,
	})
	_, url, stop := startTestServerWithResolver(t, resolver)
	defer stop()

	var kg keygenResult
	rpcCall(t, url, "pulsar.keygen", map[string]any{
		"threshold":    2,
		"participants": 3,
	}, &kg)

	// Empty chainID → gate falls through.
	resp := postSignCtx(t, url, "pulsar",
		hex.EncodeToString([]byte("no-chain-id")),
		kg.PublicKey,
		hex.EncodeToString([]byte("lux-evm-precompile-mldsa-v1")),
		"")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(resp.Body)
		t.Fatalf("empty chainID fail-OPEN broken: status=%d body=%s; want 200",
			resp.StatusCode, string(bs))
	}
}

// TestNewStaticChainProfileResolver_DefaultBehaviour exercises the
// static resolver constructor — sanity check that the constructor
// returns a resolver whose ResolveChainProfile honors the supplied
// map and falls back to def.
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
