// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// rpcRequest is the JSON-RPC 2.0 request envelope.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// rpcResponse is the JSON-RPC 2.0 response envelope.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// keygenParams is the common shape for every <scheme>.keygen call.
type keygenParams struct {
	Threshold    int `json:"threshold"`
	Participants int `json:"participants"`
}

// keygenResult is the common shape for every <scheme>.keygen response.
type keygenResult struct {
	PublicKey string   `json:"publicKey"`
	Shares    []string `json:"shares"`
}

// signParams is the common shape for every <scheme>.sign call.
type signParams struct {
	MessageHex string `json:"messageHex"`
	PubKeyHex  string `json:"pubKeyHex"`
}

// signCtxParams is the shape for ctx-bound sign methods (pulsar and
// magnetar). CtxHex is hex-encoded ctx bytes (max 255 bytes after
// decode per FIPS 204 §5.2 / FIPS 205 §10.2); empty string binds the
// empty ctx. Use the precompile constants
// `lux-evm-precompile-mldsa-v1` / `lux-evm-precompile-slhdsa-v1` to
// produce signatures that satisfy the on-chain EVM precompile's
// domain-separation contract.
//
// ChainID, when set, asserts the chain context the caller intends
// this signature to land on. The dispatcher consults the wired
// ChainProfileResolver to map ChainID → Profile; on a strict-PQ
// chain, the single-party dealer / single-validator shortcut path
// is refused (HTTP 503 + the documented body) until sister
// agents land pulsar v0.4's threshold ctx-bound path. Empty
// ChainID means "no chain context asserted"; the gate fails open
// (see profile.go::RefuseUnderStrictPQ). ChainID may also be
// supplied via the X-Chain-ID HTTP header; the JSON body field
// wins when both are set.
type signCtxParams struct {
	MessageHex string `json:"messageHex"`
	PubKeyHex  string `json:"pubKeyHex"`
	CtxHex     string `json:"ctxHex"`
	ChainID    string `json:"chainID,omitempty"`
}

// signResult is the common shape for every <scheme>.sign response.
type signResult struct {
	SignatureHex string `json:"signatureHex"`
}

// verifyParams is the common shape for every <scheme>.verify call.
type verifyParams struct {
	MessageHex   string `json:"messageHex"`
	SignatureHex string `json:"signatureHex"`
	PubKeyHex    string `json:"pubKeyHex"`
}

// verifyResult is the common shape for every <scheme>.verify response.
type verifyResult struct {
	OK bool `json:"ok"`
}

// scheme is the per-protocol handler set.
type scheme interface {
	Keygen(p keygenParams) (keygenResult, error)
	Sign(p signParams) (signResult, error)
	Verify(p verifyParams) (verifyResult, error)
}

// ctxSigner is the optional ctx-bound signing surface. Schemes that
// implement it expose `<scheme>.sign_ctx` for FIPS-204/205 §5.2/§10.2
// context-bound signatures (used by the on-chain EVM precompile
// domain-separation contract). Pulsar and magnetar implement it;
// other schemes return -32601 (method-not-found) on `<scheme>.sign_ctx`.
type ctxSigner interface {
	Sign_Ctx(p signCtxParams) (signResult, error)
}

// profileAwareCtxSigner is the strict-PQ-aware variant of ctxSigner.
// Schemes that implement it run the strict-PQ gate
// (RefuseUnderStrictPQ) at entry against the supplied chainID and
// resolver before producing a signature. Pulsar and magnetar
// implement this; other schemes fall back to plain ctxSigner. The
// resolver is supplied by the dispatcher (see Server) so call sites
// never reach across the lock to read it. A nil resolver bypasses
// the gate (documented fail-OPEN — see profile.go).
type profileAwareCtxSigner interface {
	Sign_Ctx_Profile(p signCtxParams, resolver ChainProfileResolver) (signResult, error)
}

// Server is the JSON-RPC dispatcher.
//
// Auth: a non-empty `authToken` gates every JSON-RPC request behind a
// constant-time `Authorization: Bearer <token>` comparison. Empty token
// disables the gate (used by the standalone `thresholdd` CLI for dev
// tooling on loopback). Production embedders (luxfi/mpc's mpcd) MUST
// call `SetAuthToken` with a per-cluster shared secret derived from the
// node identity — see luxfi/mpc/cmd/mpcd/main.go.
//
// Closes Red HIGH B1: an unauthenticated dispatcher on a known port is
// a signing oracle for any local process (and via SSRF, any code that
// can issue an HTTP request from inside mpcd).
type Server struct {
	mu        sync.RWMutex
	schemes   map[string]scheme
	authToken string

	// chainProfileResolver is the optional chain-profile lookup the
	// strict-PQ gate consults on Sign_Ctx. nil → gate fails open
	// (documented in profile.go::RefuseUnderStrictPQ); production
	// embedders SetChainProfileResolver at boot with an adapter
	// over luxfi/consensus/config.
	chainProfileResolver ChainProfileResolver
}

// schemeAliases maps deprecated scheme names to their canonical names
// for backward compatibility on the JSON-RPC wire. Inbound requests
// using the deprecated name are silently routed to the canonical
// scheme; outbound documentation and responses always use the
// canonical name. Remove an entry once external callers have migrated.
//
//	"corona" → "corona"  (renamed 2026-06 per AUDIT-2026-06.md §4.3
//	                        in luxfi/corona; canonical R-LWE name).
var schemeAliases = map[string]string{
	"corona": "corona",
}

// canonicalScheme normalizes an inbound scheme name through the alias
// table, returning the canonical name. Unknown names pass through
// unchanged so the caller's "unknown scheme" error path still fires.
func canonicalScheme(name string) string {
	if c, ok := schemeAliases[name]; ok {
		return c
	}
	return name
}

// NewServer builds the dispatcher with the wired schemes.
//
//	cggmp21  — Canetti-Gennaro-Goldfeder-Makriyannis-Peled 2021 ECDSA.
//	frost    — Komlo-Goldberg FROST Schnorr.
//	bls      — BLS12-381 t-of-n via Shamir + Lagrange.
//	pulsar   — M-LWE post-quantum threshold (luxfi/pulsar). Wired via
//	           the canonical PULG/Signature wire codec; see pulsar.go.
//	corona   — Ring-LWE post-quantum threshold (luxfi/corona). Wired
//	           2026-05-31 once corona threshold/wire.go shipped canonical
//	           Signature.MarshalBinary / GroupKey.MarshalBinary /
//	           VerifyBytes. Trust-model disclosure on the dispatcher's
//	           keygen is in corona.go. Legacy wire-name "corona" is
//	           accepted on read via schemeAliases (deprecated; emit
//	           "corona" on all new clients).
//	magnetar — SLH-DSA per-validator-standalone (luxfi/magnetar). Wired
//	           via the canonical MAGS/MAGG wire codec; see magnetar.go.
//	doerner  — Doerner-Kondi-Lee-Shelat 2018 2-of-n ECDSA. Reserved
//	           namespace; upstream impl is non-functional. See doerner.go.
func NewServer() (*Server, error) {
	s := &Server{schemes: make(map[string]scheme)}

	s.schemes["cggmp21"] = newCGGMP21Scheme()
	s.schemes["frost"] = newFrostScheme()
	s.schemes["pulsar"] = newPulsarScheme()
	s.schemes["corona"] = newCoronaScheme()
	s.schemes["magnetar"] = newMagnetarScheme()
	s.schemes["bls"] = newBLSScheme()
	s.schemes["doerner"] = newDoernerScheme()

	return s, nil
}

// SetAuthToken installs a bearer token. Subsequent requests must carry
// `Authorization: Bearer <token>` or receive HTTP 401. Empty token
// removes the gate. Constant-time comparison defeats timing attacks.
func (s *Server) SetAuthToken(token string) {
	s.mu.Lock()
	s.authToken = token
	s.mu.Unlock()
}

// SetChainProfileResolver installs the chain-profile resolver the
// strict-PQ gate consults on Sign_Ctx. Passing nil clears the
// resolver (the gate then fails open). Production embedders wire an
// adapter over luxfi/consensus/config; the standalone thresholdd
// CLI leaves it nil for dev tooling.
func (s *Server) SetChainProfileResolver(r ChainProfileResolver) {
	s.mu.Lock()
	s.chainProfileResolver = r
	s.mu.Unlock()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth gate. Read under the same RLock as the schemes map so
	// SetAuthToken can flip the gate atomically.
	s.mu.RLock()
	wantTok := s.authToken
	s.mu.RUnlock()
	if wantTok != "" {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if !strings.HasPrefix(got, prefix) ||
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(wantTok)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
	if err != nil {
		writeError(w, nil, -32700, "read body: "+err.Error())
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, nil, -32700, "parse error: "+err.Error())
		return
	}
	if req.JSONRPC != "2.0" {
		writeError(w, req.ID, -32600, "invalid jsonrpc version")
		return
	}

	schemeName, op, ok := splitMethod(req.Method)
	if !ok {
		writeError(w, req.ID, -32601, "method not found: "+req.Method)
		return
	}
	// Normalize legacy wire names (e.g. "corona" → "corona") so old
	// clients continue to dispatch correctly. See schemeAliases for the
	// deprecation list.
	schemeName = canonicalScheme(schemeName)

	s.mu.RLock()
	sc, exists := s.schemes[schemeName]
	s.mu.RUnlock()
	if !exists {
		writeError(w, req.ID, -32601, "unknown scheme: "+schemeName)
		return
	}

	switch op {
	case "keygen":
		var p keygenParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeError(w, req.ID, -32602, "invalid params: "+err.Error())
			return
		}
		res, err := sc.Keygen(p)
		if err != nil {
			writeError(w, req.ID, -32000, err.Error())
			return
		}
		writeResult(w, req.ID, res)
	case "sign":
		var p signParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeError(w, req.ID, -32602, "invalid params: "+err.Error())
			return
		}
		res, err := sc.Sign(p)
		if err != nil {
			writeError(w, req.ID, -32000, err.Error())
			return
		}
		writeResult(w, req.ID, res)
	case "sign_ctx":
		cs, ok := sc.(ctxSigner)
		if !ok {
			writeError(w, req.ID, -32601, "scheme does not support sign_ctx: "+schemeName)
			return
		}
		var p signCtxParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeError(w, req.ID, -32602, "invalid params: "+err.Error())
			return
		}
		// Plumb chain ID: JSON body wins; X-Chain-ID header
		// supplies it when the body omits it. Empty means "no
		// chain asserted" → gate falls through (see profile.go).
		if p.ChainID == "" {
			p.ChainID = r.Header.Get("X-Chain-ID")
		}
		// Profile-aware path: schemes that implement
		// profileAwareCtxSigner consult the strict-PQ gate
		// themselves at entry. Plain ctxSigner is the legacy path
		// (gate not consulted). Snapshot the resolver under RLock
		// so SetChainProfileResolver can swap atomically.
		s.mu.RLock()
		resolver := s.chainProfileResolver
		s.mu.RUnlock()
		var (
			res signResult
			err error
		)
		if pas, ok := sc.(profileAwareCtxSigner); ok {
			res, err = pas.Sign_Ctx_Profile(p, resolver)
		} else {
			res, err = cs.Sign_Ctx(p)
		}
		if err != nil {
			// Strict-PQ refusal: HTTP 503 + the documented body
			// (see profile.go::strictPQRefusalBody). NOT a
			// JSON-RPC error envelope — the documented contract
			// says HTTP 503 because the dispatcher temporarily
			// cannot produce a strict-PQ-compliant Sign_Ctx
			// signature, which is a service-unavailable
			// condition, not a request error.
			if errors.Is(err, ErrRefusedUnderStrictPQ) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strictPQRefusalBody))
				return
			}
			writeError(w, req.ID, -32000, err.Error())
			return
		}
		writeResult(w, req.ID, res)
	case "verify":
		var p verifyParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeError(w, req.ID, -32602, "invalid params: "+err.Error())
			return
		}
		res, err := sc.Verify(p)
		if err != nil {
			writeError(w, req.ID, -32000, err.Error())
			return
		}
		writeResult(w, req.ID, res)
	default:
		writeError(w, req.ID, -32601, "unknown op: "+op)
	}
}

func splitMethod(m string) (string, string, bool) {
	dot := strings.IndexByte(m, '.')
	if dot < 1 || dot == len(m)-1 {
		return "", "", false
	}
	return m[:dot], m[dot+1:], true
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// validateKeygenParams enforces the shared invariants once.
func validateKeygenParams(p keygenParams) error {
	if p.Participants <= 0 {
		return fmt.Errorf("participants must be > 0, got %d", p.Participants)
	}
	if p.Threshold <= 0 || p.Threshold > p.Participants {
		return fmt.Errorf("threshold must be in [1, %d], got %d", p.Participants, p.Threshold)
	}
	return nil
}
