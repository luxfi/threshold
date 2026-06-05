// SPDX-License-Identifier: BSD-3-Clause
package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

// zap_helpers.go — ZAP-side dispatcher harness for the e2e tests.
// The prior HTTP+JSON+hex harness was deleted alongside the HTTP path
// in pkg/thresholdd; this file restores the same `rpcCall` ergonomics
// (method-name + JSON params → json.RawMessage result) on top of the
// ZAP byte-passthrough wire.
//
// One ZapClient per test process, cached by addr → client. The harness
// owns connection lifetimes; tests pass the addr (returned by
// startZapDispatcher) around as if it were a URL.

// dispatcherHandle is the test-facing handle for a running ZAP
// dispatcher. The `addr` field is opaque to the test and is the only
// thing rpcCall takes.
type dispatcherHandle struct {
	addr string
	stop func()
}

// startZapDispatcher brings up a ZAP dispatcher on an ephemeral
// loopback port and returns its addr + a cleanup func. Replaces the
// httptest.NewServer(thresholdd.NewServer()) pattern from the prior
// HTTP-driven harness.
func startZapDispatcher(t *testing.T) *dispatcherHandle {
	t.Helper()
	port := allocPort(t)
	srv, err := thresholdd.NewZapServer(thresholdd.ZapServerConfig{
		NodeID: "thresholdd-e2e",
		Port:   port,
	})
	if err != nil {
		t.Fatalf("thresholdd.NewZapServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("ZapServer.Start: %v", err)
	}
	// Give the accept loop a beat to register.
	time.Sleep(20 * time.Millisecond)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	return &dispatcherHandle{addr: addr, stop: srv.Stop}
}

// allocPort grabs an ephemeral loopback port the kernel just freed.
func allocPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

// zapClientCache memoises a ZapClient per addr so consecutive
// rpcCall invocations reuse the same connection. The cache is
// process-global because the tests are single-shot and the resource
// cost of a new conn per call would dominate the bench numbers.
var (
	zapClientMu    sync.Mutex
	zapClientCache = map[string]*thresholdd.ZapClient{}
)

// getZapClient returns a cached ZapClient for addr, creating one on
// first use. Threadsafe; the cache lives for the duration of the
// test binary.
func getZapClient(addr string) (*thresholdd.ZapClient, error) {
	zapClientMu.Lock()
	defer zapClientMu.Unlock()
	if c, ok := zapClientCache[addr]; ok {
		return c, nil
	}
	c, err := thresholdd.ConnectZap(context.Background(), addr,
		thresholdd.WithZapCallTimeout(2*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("connect zap: %w", err)
	}
	zapClientCache[addr] = c
	return c, nil
}

// rpcCall is the ZAP-backed replacement for the prior HTTP+JSON+hex
// helper. Signature is unchanged: (addr, method, params) →
// (json.RawMessage, error). Params and result are kept as the same
// hex-keyed JSON shape so the existing test bodies do not need to
// change — the helper translates to/from the ZAP raw-byte wire.
//
// The `url` parameter from the prior helper is now the dispatcher's
// host:port addr; tests pass `dispatcherHandle.addr` here.
func rpcCall(addr, method string, params any) (json.RawMessage, error) {
	c, err := getZapClient(addr)
	if err != nil {
		return nil, err
	}
	scheme, op, ok := splitMethod(method)
	if !ok {
		return nil, fmt.Errorf("rpc method %q is not <scheme>.<op>", method)
	}

	// Coerce params into a map so we can pluck the hex-string fields
	// the test bodies use.
	m, ok := params.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rpcCall params not map[string]any (got %T)", params)
	}
	ctx := context.Background()

	switch op {
	case "keygen":
		thrI, _ := m["threshold"].(int)
		pcsI, _ := m["participants"].(int)
		pubKey, shares, err := c.Keygen(ctx, scheme, thrI, pcsI)
		if err != nil {
			return nil, fmt.Errorf("zap keygen: %w", err)
		}
		out := map[string]any{
			"publicKey": hex.EncodeToString(pubKey),
			"shares":    shares,
		}
		return json.Marshal(out)

	case "sign":
		msgHex, _ := m["messageHex"].(string)
		pubHex, _ := m["pubKeyHex"].(string)
		msg, err := hex.DecodeString(msgHex)
		if err != nil {
			return nil, fmt.Errorf("decode messageHex: %w", err)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			return nil, fmt.Errorf("decode pubKeyHex: %w", err)
		}
		sig, err := c.Sign(ctx, scheme, msg, pub)
		if err != nil {
			return nil, fmt.Errorf("zap sign: %w", err)
		}
		out := map[string]any{"signatureHex": hex.EncodeToString(sig)}
		return json.Marshal(out)

	case "verify":
		msgHex, _ := m["messageHex"].(string)
		sigHex, _ := m["signatureHex"].(string)
		pubHex, _ := m["pubKeyHex"].(string)
		msg, err := hex.DecodeString(msgHex)
		if err != nil {
			return nil, fmt.Errorf("decode messageHex: %w", err)
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return nil, fmt.Errorf("decode signatureHex: %w", err)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			return nil, fmt.Errorf("decode pubKeyHex: %w", err)
		}
		ok, err := c.Verify(ctx, scheme, msg, sig, pub)
		if err != nil {
			return nil, fmt.Errorf("zap verify: %w", err)
		}
		out := map[string]any{"ok": ok}
		return json.Marshal(out)

	default:
		return nil, fmt.Errorf("rpc op %q not supported (use keygen/sign/verify)", op)
	}
}

func splitMethod(m string) (scheme, op string, ok bool) {
	for i, c := range m {
		if c == '.' {
			if i == 0 || i == len(m)-1 {
				return "", "", false
			}
			return m[:i], m[i+1:], true
		}
	}
	return "", "", false
}
