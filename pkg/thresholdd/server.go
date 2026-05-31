// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"crypto/subtle"
	"encoding/json"
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
//	           keygen is in corona.go.
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
