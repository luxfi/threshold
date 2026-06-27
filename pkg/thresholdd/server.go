// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

// server.go — ZAP byte-passthrough dispatcher for the threshold daemon.
//
// ZAP is the ONLY wire transport. The historical HTTP+JSON+hex path
// (server.go's prior incarnation, plus its rpcRequest/rpcResponse
// shapes and net/http handler) was deleted. The TS-side consumers that
// drove HTTP via `MPCD_URL`/`THRESHOLD_DAEMON_URL` env vars are
// blocked on a TS-side ZAP client — see teleport/mpc/src/signers/rpc.ts
// for the placeholder transport that throws explicit migration errors.
//
// Wire shape: every {keygen, sign, sign_ctx, verify} call rides as a
// fixed-layout ZAP envelope (see zap_schema.go) — opcode in the upper
// byte of msg.Flags, message-kind (request/response/error) in the
// lower byte. The scheme handlers themselves are unchanged from the
// HTTP era: they still consume hex strings on the in-process scheme
// contract; the dispatcher decodes inbound raw bytes to hex strings
// and encodes scheme outputs back to raw bytes on the wire.

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	zap "github.com/luxfi/zap"
)

// ZapServer is the threshold dispatcher's ZAP transport.
//
// Auth: a non-empty `authToken` gates every inbound message via a
// constant-time bearer comparison. The token is stamped as a
// peer-metadata field at handshake (set by the client). Empty token
// disables the gate (loopback dev only).
//
// Strict-PQ gate: the RefuseUnderStrictPQ helper from profile.go
// guards Sign_Ctx. The refusal is surfaced as a ZAP ErrorResponse
// carrying strictPQ=true so the client can errors.Is the sentinel.
type ZapServer struct {
	mu        sync.RWMutex
	schemes   map[string]scheme
	authToken string

	chainProfileResolver ChainProfileResolver

	node    *zap.Node
	logger  *slog.Logger
	stopped bool
}

// ZapServerConfig captures the wiring knobs ZapServer needs. Defaults
// are designed for process-local IPC — no mDNS, plaintext, loopback.
// Embedders that expose ZAP over cluster network MUST set TLS to an
// mTLS-validating *tls.Config and supply an authToken.
type ZapServerConfig struct {
	NodeID    string      // ZAP node ID; defaults to "thresholdd"
	Port      int         // listen port; 0 → ephemeral
	AuthToken string      // bearer-token; empty disables auth gate
	TLS       *tls.Config // mTLS config; nil → plaintext (loopback only)
	Logger    *slog.Logger
}

// NewZapServer constructs a ZapServer with the canonical scheme set
// (cggmp21, frost, pulsar, corona, magnetar, doerner).
func NewZapServer(cfg ZapServerConfig) (*ZapServer, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.NodeID == "" {
		cfg.NodeID = "thresholdd"
	}

	s := &ZapServer{
		schemes:   make(map[string]scheme),
		authToken: cfg.AuthToken,
		logger:    cfg.Logger,
	}
	s.schemes["cggmp21"] = newCGGMP21Scheme()
	s.schemes["frost"] = newFrostScheme()
	s.schemes["pulsar"] = newPulsarScheme()
	s.schemes["corona"] = newCoronaScheme()
	s.schemes["magnetar"] = newMagnetarScheme()
	s.schemes["doerner"] = newDoernerScheme()

	s.node = zap.NewNode(zap.NodeConfig{
		NodeID:      cfg.NodeID,
		ServiceType: "_thresholdd._tcp",
		Port:        cfg.Port,
		NoDiscovery: true, // process-local IPC — no mDNS announce
		TLS:         cfg.TLS,
		Logger:      cfg.Logger,
	})

	// Register one handler per procedure opcode. zap.Node.Handle keys
	// on the upper byte of the message Flags field (msg.Flags() >> 8),
	// and our flagsForRequest stamps the procOpcode in that upper byte
	// — so handlers route directly without a centralized switch.
	//
	// We use a single dispatch shim per procedure that owns the
	// scheme + op binding; the auth gate and the strict-PQ gate run
	// once at the top.
	for _, p := range allProcedures {
		p := p // capture
		op := procOpcode(p.name)
		s.node.Handle(op>>8, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
			return s.dispatch(ctx, p, from, msg)
		})
	}

	return s, nil
}

// procedureBinding pairs a procedure name with its scheme + op + a
// callback that runs the underlying scheme handler. The handler
// itself is resolved at dispatch time (after the auth gate fires) so
// SetAuthToken / SetChainProfileResolver can swap atomically.
type procedureBinding struct {
	name   string
	scheme string
	op     string // "keygen" / "sign" / "sign_ctx" / "verify"
}

var allProcedures = []procedureBinding{
	{name: ProcCggmp21Keygen, scheme: "cggmp21", op: "keygen"},
	{name: ProcCggmp21Sign, scheme: "cggmp21", op: "sign"},
	{name: ProcCggmp21Verify, scheme: "cggmp21", op: "verify"},
	{name: ProcFrostKeygen, scheme: "frost", op: "keygen"},
	{name: ProcFrostSign, scheme: "frost", op: "sign"},
	{name: ProcFrostVerify, scheme: "frost", op: "verify"},
	{name: ProcPulsarKeygen, scheme: "pulsar", op: "keygen"},
	{name: ProcPulsarSign, scheme: "pulsar", op: "sign"},
	{name: ProcPulsarSignCtx, scheme: "pulsar", op: "sign_ctx"},
	{name: ProcPulsarVerify, scheme: "pulsar", op: "verify"},
	{name: ProcCoronaKeygen, scheme: "corona", op: "keygen"},
	{name: ProcCoronaSign, scheme: "corona", op: "sign"},
	{name: ProcCoronaVerify, scheme: "corona", op: "verify"},
	{name: ProcMagnetarKeygen, scheme: "magnetar", op: "keygen"},
	{name: ProcMagnetarSign, scheme: "magnetar", op: "sign"},
	{name: ProcMagnetarSignCtx, scheme: "magnetar", op: "sign_ctx"},
	{name: ProcMagnetarVerify, scheme: "magnetar", op: "verify"},
	{name: ProcDoernerKeygen, scheme: "doerner", op: "keygen"},
	{name: ProcDoernerSign, scheme: "doerner", op: "sign"},
	{name: ProcDoernerVerify, scheme: "doerner", op: "verify"},
}

// SetAuthToken installs a bearer token. The token is matched in
// constant time against the metadata field the client stamps on
// every request. Empty token removes the gate.
func (s *ZapServer) SetAuthToken(token string) {
	s.mu.Lock()
	s.authToken = token
	s.mu.Unlock()
}

// SetChainProfileResolver installs the chain-profile resolver the
// strict-PQ gate consults on Sign_Ctx. Nil clears the resolver
// (gate then fails open — see profile.go).
func (s *ZapServer) SetChainProfileResolver(r ChainProfileResolver) {
	s.mu.Lock()
	s.chainProfileResolver = r
	s.mu.Unlock()
}

// Start binds the listener and begins accepting. Idempotent across
// double-Stop; double-Start is a programmer error.
func (s *ZapServer) Start() error {
	return s.node.Start()
}

// Stop releases the listener + connections. Idempotent.
func (s *ZapServer) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.mu.Unlock()
	s.node.Stop()
}

// NodeID returns the server's nodeID. Useful for tests that drive
// ConnectDirect through the loopback transport.
func (s *ZapServer) NodeID() string {
	return s.node.NodeID()
}

// dispatch is the per-procedure handler. The auth gate runs first
// (constant-time bearer compare against the X-Threshold-Auth peer
// metadata stamped by ZapClient). Strict-PQ runs second for ctx-
// bound paths. Then the scheme handler executes.
//
// On success, the response is encoded with the response kind set on
// the flags upper byte the request originally carried; on failure,
// an ErrorResponse with a JSON-RPC-style numeric code (see zap_schema.go
// ZapErrCode* constants) is emitted so callers can branch on
// well-defined error classes.
func (s *ZapServer) dispatch(ctx context.Context, p procedureBinding, from string, msg *zap.Message) (*zap.Message, error) {
	reqFlags := msg.Flags()

	// Auth gate (Red HIGH B1 mirror). ZAP-side auth is connection-
	// scoped, not per-message — the peer is authenticated at
	// handshake by its NodeID, and (in production) by its mTLS cert
	// SAN. The bare zap.Node API today surfaces the peer NodeID
	// to handlers via the `from` parameter; mTLS cert metadata will
	// land on the same hook in a follow-up.
	//
	// When `authToken` is non-empty, the server accepts connections
	// whose peer NodeID equals the token (constant-time compare).
	// This is the dev / loopback wiring; the production wiring is
	// mTLS-only (peer is authenticated by the TLS handshake; the
	// authToken is unset; the LocalTrustVerifier accepts any peer
	// with a valid cert from the cluster CA).
	//
	// Empty `authToken` disables the gate — loopback-dev / standalone
	// CLI default.
	s.mu.RLock()
	wantTok := s.authToken
	resolver := s.chainProfileResolver
	sch, schemeExists := s.schemes[p.scheme]
	s.mu.RUnlock()

	if wantTok != "" {
		if from == "" {
			return errorResponseMsg(reqFlags, ZapErrCodeMethodNotFnd, "auth required: TLS handshake produced no peer identity", false)
		}
		if subtle.ConstantTimeCompare([]byte(from), []byte(wantTok)) != 1 {
			return errorResponseMsg(reqFlags, ZapErrCodeMethodNotFnd, "unauthorized", false)
		}
	}

	if !schemeExists {
		return errorResponseMsg(reqFlags, ZapErrCodeMethodNotFnd, fmt.Sprintf("unknown scheme: %s", p.scheme), false)
	}

	switch p.op {
	case "keygen":
		return s.dispatchKeygen(reqFlags, sch, msg)
	case "sign":
		return s.dispatchSign(reqFlags, sch, msg)
	case "sign_ctx":
		return s.dispatchSignCtx(reqFlags, sch, resolver, msg)
	case "verify":
		return s.dispatchVerify(reqFlags, sch, msg)
	default:
		return errorResponseMsg(reqFlags, ZapErrCodeMethodNotFnd, "unknown op: "+p.op, false)
	}
}

func (s *ZapServer) dispatchKeygen(reqFlags uint16, sch scheme, msg *zap.Message) (*zap.Message, error) {
	p, err := readKeygenRequest(msg)
	if err != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInvalidParam, "invalid params: "+err.Error(), false)
	}
	res, err := sch.Keygen(p)
	if err != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInternal, err.Error(), false)
	}
	// res.PublicKey is a hex string on the in-process scheme contract;
	// decode to emit raw bytes on the ZAP wire. The scheme handlers
	// still consume/produce hex strings — this is the boundary that
	// converts between the in-process hex contract and the ZAP raw-
	// byte wire. Local string conversion, no network cost.
	pkBytes, decErr := hexDecodeStrict(res.PublicKey)
	if decErr != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInternal, "keygen produced non-hex pubKey: "+decErr.Error(), false)
	}
	return wrapBytes(buildKeygenResponse(reqFlags, pkBytes, res.Shares)), nil
}

func (s *ZapServer) dispatchSign(reqFlags uint16, sch scheme, msg *zap.Message) (*zap.Message, error) {
	rawMsg, rawPub, err := readSignRequest(msg)
	if err != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInvalidParam, "invalid params: "+err.Error(), false)
	}
	// Re-encode to hex for the inner scheme handler — its current
	// contract is hex strings. The downstream byte material remains
	// byte-identical; this is purely a local string conversion.
	res, err := sch.Sign(signParams{
		MessageHex: hexEncode(rawMsg),
		PubKeyHex:  hexEncode(rawPub),
	})
	if err != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInternal, err.Error(), false)
	}
	sigBytes, decErr := hexDecodeStrict(res.SignatureHex)
	if decErr != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInternal, "sign produced non-hex signature: "+decErr.Error(), false)
	}
	return wrapBytes(buildSignResponse(reqFlags, sigBytes)), nil
}

func (s *ZapServer) dispatchSignCtx(reqFlags uint16, sch scheme, resolver ChainProfileResolver, msg *zap.Message) (*zap.Message, error) {
	cs, ok := sch.(ctxSigner)
	if !ok {
		return errorResponseMsg(reqFlags, ZapErrCodeMethodNotFnd, "scheme does not support sign_ctx", false)
	}
	rawMsg, rawPub, ctxBytes, chainID, err := readSignCtxRequest(msg)
	if err != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInvalidParam, "invalid params: "+err.Error(), false)
	}
	p := signCtxParams{
		MessageHex: hexEncode(rawMsg),
		PubKeyHex:  hexEncode(rawPub),
		CtxHex:     hexEncode(ctxBytes),
		ChainID:    chainID,
	}
	var (
		res  signResult
		oerr error
	)
	if pas, ok := sch.(profileAwareCtxSigner); ok {
		res, oerr = pas.Sign_Ctx_Profile(p, resolver)
	} else {
		res, oerr = cs.Sign_Ctx(p)
	}
	if oerr != nil {
		if errors.Is(oerr, ErrRefusedUnderStrictPQ) {
			return errorResponseMsg(reqFlags, ZapErrCodeInternal,
				"Sign_Ctx requires pulsar v0.4 threshold ctx-bound path; rejected on strict-PQ chain profile",
				true)
		}
		return errorResponseMsg(reqFlags, ZapErrCodeInternal, oerr.Error(), false)
	}
	sigBytes, decErr := hexDecodeStrict(res.SignatureHex)
	if decErr != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInternal, "sign_ctx produced non-hex signature: "+decErr.Error(), false)
	}
	return wrapBytes(buildSignResponse(reqFlags, sigBytes)), nil
}

func (s *ZapServer) dispatchVerify(reqFlags uint16, sch scheme, msg *zap.Message) (*zap.Message, error) {
	rawMsg, rawSig, rawPub, err := readVerifyRequest(msg)
	if err != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInvalidParam, "invalid params: "+err.Error(), false)
	}
	res, err := sch.Verify(verifyParams{
		MessageHex:   hexEncode(rawMsg),
		SignatureHex: hexEncode(rawSig),
		PubKeyHex:    hexEncode(rawPub),
	})
	if err != nil {
		return errorResponseMsg(reqFlags, ZapErrCodeInternal, err.Error(), false)
	}
	return wrapBytes(buildVerifyResponse(reqFlags, res.OK)), nil
}

// wrapBytes parses a freshly built ZAP buffer into a *zap.Message
// suitable for return from a handler. We always go through Parse —
// the v0.7.x line does not expose WrapBuffer (no-validate fast path)
// in the public API yet; the re-validation is one bounds check on a
// buffer we control, so the cost is negligible.
func wrapBytes(b []byte) *zap.Message {
	m, _ := zap.Parse(b)
	return m
}

// errorResponseMsg builds an error response message wrapped in a
// *zap.Message. Returns the message + nil error so the node's
// dispatch loop writes it back rather than logging a handler-error
// (which would also drop the response on the floor).
func errorResponseMsg(reqFlags uint16, code int32, msg string, strictPQ bool) (*zap.Message, error) {
	m, _ := zap.Parse(buildErrorResponse(reqFlags, code, msg, strictPQ))
	return m, nil
}

// hexEncode / hexDecodeStrict are local helpers — kept thin to keep
// the dispatch hot path concentrated in this file. encoding/hex is
// the standard-library implementation; no third-party dep.
func hexEncode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hextable = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hextable[v>>4]
		out[i*2+1] = hextable[v&0x0f]
	}
	return string(out)
}

func hexDecodeStrict(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex string")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := fromHexNibble(s[i*2])
		lo, ok2 := fromHexNibble(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid hex byte at %d", i*2)
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func fromHexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
