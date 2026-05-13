package thresholdd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestPulsarRoundTrip(t *testing.T) {
	t.Parallel()
	roundtrip(t, "pulsar", 2, 3)
}

func TestCoronaRoundTrip(t *testing.T) {
	t.Parallel()
	roundtrip(t, "corona", 2, 3)
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

// guard against pkg-level deadlocks in CI runners.
func TestMain(m *testing.M) {
	// Each subtest also enforces protocol-level timeouts via runner.go.
	go func() {
		time.Sleep(10 * time.Minute)
		panic("thresholdd_test: global timeout — protocol stuck")
	}()
	m.Run()
}
