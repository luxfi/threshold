// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

// client.go — ZAP client for the threshold dispatcher.
//
// Go consumers (luxfi/mpc's production embedders, e2e tests, the
// dispatcher's own bench harness) build a *ZapClient via
// ConnectZap(addr, opts...) and invoke per-scheme methods. The
// TS-side counterpart in teleport/mpc/src/signers/rpc.ts is pending
// a ZAP JS client; until that lands the TS signers' HTTP transport
// fails closed with an explicit migration error.
//
// Wire bytes: requests carry { Threshold/Participants } or
// { Message, PubKey [, Ctx, ChainID, Signature] } as raw bytes inside
// a fixed ZAP envelope. Responses carry { PubKey, Shares blob } for
// keygen or { Signature } for sign — all bytes, no hex.
//
// Connection model: one ZapClient = one connection to one server,
// reused across calls. The underlying zap.Node multiplexes request /
// response correlation via a per-request reqID + response channel
// (zap/node.go::dispatchLoop). Connection-level concurrency is bound
// by the conn's read-loop goroutine; the call surface is goroutine-
// safe.

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	zap "github.com/luxfi/zap"
)

// ZapClient is a process-local ZAP transport client for thresholdd.
//
// Construct via ConnectZap(addr, opts...). Always defer Close on the
// returned client. The client owns a single zap.Node (used purely as
// a client — its listener is unused). Calls multiplex through the
// underlying Node's per-conn correlation map.
type ZapClient struct {
	node      *zap.Node
	peerID    string // resolved at handshake; required for node.Call
	timeout   time.Duration
	authToken string
	logger    *slog.Logger

	mu     sync.Mutex
	closed bool
}

// ZapClientOptions configure ConnectZap. Construct via WithZap*
// options.
type ZapClientOptions struct {
	NodeID      string
	CallTimeout time.Duration
	AuthToken   string
	TLS         *tls.Config
	Logger      *slog.Logger
}

// ZapClientOption is the functional-option knob.
type ZapClientOption func(*ZapClientOptions)

// WithZapNodeID names the caller for the ZAP handshake.
func WithZapNodeID(id string) ZapClientOption {
	return func(o *ZapClientOptions) { o.NodeID = id }
}

// WithZapCallTimeout caps every call's wait for a response. Zero =
// no transport-level timeout (still bounded by ctx).
func WithZapCallTimeout(d time.Duration) ZapClientOption {
	return func(o *ZapClientOptions) { o.CallTimeout = d }
}

// WithZapAuthToken stamps a bearer token onto every request. Must
// match the server's SetAuthToken value. Empty token = no auth gate.
func WithZapAuthToken(tok string) ZapClientOption {
	return func(o *ZapClientOptions) { o.AuthToken = tok }
}

// WithZapTLS configures TLS on the client side. nil = plaintext
// (loopback only). Production deployments MUST use mTLS.
func WithZapTLS(cfg *tls.Config) ZapClientOption {
	return func(o *ZapClientOptions) { o.TLS = cfg }
}

// WithZapLogger sets the structured logger.
func WithZapLogger(l *slog.Logger) ZapClientOption {
	return func(o *ZapClientOptions) { o.Logger = l }
}

// ConnectZap dials the threshold ZAP server at the given address and
// returns a ready-to-use *ZapClient. The connection is established
// synchronously; any failure here means no calls succeed afterwards
// either.
//
// addr is a host:port. The dialer goes through zap.Node.ConnectDirect
// so it bypasses mDNS — appropriate for process-local IPC and
// explicit-endpoint deployments.
func ConnectZap(ctx context.Context, addr string, opts ...ZapClientOption) (*ZapClient, error) {
	o := defaultZapClientOpts()
	for _, opt := range opts {
		opt(&o)
	}
	if o.NodeID == "" {
		o.NodeID = fmt.Sprintf("zapclient-%d", time.Now().UnixNano()&0xffffff)
	}

	n := zap.NewNode(zap.NodeConfig{
		NodeID:      o.NodeID,
		ServiceType: "_thresholdd._tcp",
		Port:        0, // ephemeral; client-side listener is unused
		NoDiscovery: true,
		TLS:         o.TLS,
		Logger:      o.Logger,
	})
	if err := n.Start(); err != nil {
		return nil, fmt.Errorf("zapclient: node start: %w", err)
	}
	if err := n.ConnectDirect(addr); err != nil {
		n.Stop()
		return nil, fmt.Errorf("zapclient: connect %s: %w", addr, err)
	}

	// The server's NodeID is established during handshake; node.Peers()
	// returns it after ConnectDirect succeeds. We snapshot it once so
	// every Call routes to the correct peer without re-checking.
	peers := n.Peers()
	if len(peers) == 0 {
		n.Stop()
		return nil, fmt.Errorf("zapclient: handshake produced no peers at %s", addr)
	}
	return &ZapClient{
		node:      n,
		peerID:    peers[0],
		timeout:   o.CallTimeout,
		authToken: o.AuthToken,
		logger:    o.Logger,
	}, nil
}

// Close releases the underlying zap.Node. Idempotent.
func (c *ZapClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.node.Stop()
	return nil
}

// callRaw issues a request with raw ZAP bytes and waits for the
// matching response message. The timeout is the min of c.timeout and
// the caller's ctx deadline.
func (c *ZapClient) callRaw(ctx context.Context, reqBytes []byte) (*zap.Message, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := zap.Parse(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("zapclient: build request: %w", err)
	}
	return c.node.Call(ctx, c.peerID, req)
}

// errorFromResponse extracts a (code, msg, strictPQ) tuple from a
// response that was tagged as ZapKindError. Callers that branch on
// strictPQ check the bool first.
func errorFromResponse(m *zap.Message) (zapErrorPayload, bool) {
	if kindFromFlags(m.Flags()) != ZapKindError {
		return zapErrorPayload{}, false
	}
	p, err := readErrorResponse(m)
	if err != nil {
		return zapErrorPayload{}, false
	}
	return p, true
}

// Keygen runs <scheme>.keygen over the ZAP wire and returns the raw
// PublicKey bytes + decoded share-IDs. Pass the PublicKey directly to
// Sign / Verify; the wire is byte-passthrough end to end.
func (c *ZapClient) Keygen(ctx context.Context, scheme string, threshold, participants int) (pubKey []byte, shares []string, err error) {
	procName := scheme + ".keygen"
	if !knownProcedure(procName) {
		return nil, nil, fmt.Errorf("zapclient: unknown procedure %q", procName)
	}
	reqBytes := buildKeygenRequest(procName, keygenParams{Threshold: threshold, Participants: participants})
	resp, err := c.callRaw(ctx, reqBytes)
	if err != nil {
		return nil, nil, err
	}
	if errPayload, isErr := errorFromResponse(resp); isErr {
		return nil, nil, fmt.Errorf("zap rpc error %d: %s", errPayload.Code, errPayload.Message)
	}
	return readKeygenResponse(resp)
}

// Sign runs <scheme>.sign over the ZAP wire and returns the raw
// signature bytes. msg + pubKey are bytes; the wire passes them
// through without hex.
func (c *ZapClient) Sign(ctx context.Context, scheme string, msg, pubKey []byte) ([]byte, error) {
	procName := scheme + ".sign"
	if !knownProcedure(procName) {
		return nil, fmt.Errorf("zapclient: unknown procedure %q", procName)
	}
	reqBytes := buildSignRequest(procName, msg, pubKey)
	resp, err := c.callRaw(ctx, reqBytes)
	if err != nil {
		return nil, err
	}
	if errPayload, isErr := errorFromResponse(resp); isErr {
		return nil, fmt.Errorf("zap rpc error %d: %s", errPayload.Code, errPayload.Message)
	}
	return readSignResponse(resp)
}

// SignCtx runs <scheme>.sign_ctx (pulsar and magnetar only). chainID
// flows through to the strict-PQ gate on the server; pass empty to
// signal "no chain context asserted".
//
// On strict-PQ refusal the returned error wraps
// ErrRefusedUnderStrictPQ so callers branch via errors.Is.
func (c *ZapClient) SignCtx(ctx context.Context, scheme string, msg, pubKey, signCtx []byte, chainID string) ([]byte, error) {
	procName := scheme + ".sign_ctx"
	if !knownProcedure(procName) {
		return nil, fmt.Errorf("zapclient: unknown procedure %q", procName)
	}
	reqBytes := buildSignCtxRequest(procName, msg, pubKey, signCtx, chainID)
	resp, err := c.callRaw(ctx, reqBytes)
	if err != nil {
		return nil, err
	}
	if errPayload, isErr := errorFromResponse(resp); isErr {
		if errPayload.StrictPQ {
			return nil, fmt.Errorf("%w: %s", ErrRefusedUnderStrictPQ, errPayload.Message)
		}
		return nil, fmt.Errorf("zap rpc error %d: %s", errPayload.Code, errPayload.Message)
	}
	return readSignResponse(resp)
}

// Verify runs <scheme>.verify over the ZAP wire. Returns the OK
// boolean from the kernel; transport-level errors (auth failure,
// unknown scheme) return a non-nil err.
func (c *ZapClient) Verify(ctx context.Context, scheme string, msg, sig, pubKey []byte) (bool, error) {
	procName := scheme + ".verify"
	if !knownProcedure(procName) {
		return false, fmt.Errorf("zapclient: unknown procedure %q", procName)
	}
	reqBytes := buildVerifyRequest(procName, msg, sig, pubKey)
	resp, err := c.callRaw(ctx, reqBytes)
	if err != nil {
		return false, err
	}
	if errPayload, isErr := errorFromResponse(resp); isErr {
		return false, fmt.Errorf("zap rpc error %d: %s", errPayload.Code, errPayload.Message)
	}
	return readVerifyResponse(resp)
}

// knownProcedure reports whether the procedure name is in the
// dispatcher's compile-time registration list. Used by the client to
// fail-fast on a typo before round-tripping the network.
func knownProcedure(name string) bool {
	for _, p := range allProcedures {
		if p.name == name {
			return true
		}
	}
	return false
}

func defaultZapClientOpts() ZapClientOptions {
	return ZapClientOptions{
		CallTimeout: 30 * time.Second,
		Logger:      slog.Default(),
	}
}
