// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"fmt"
)

// types.go — scheme-handler shape and shared parameter types.
//
// The scheme handlers are wire-transport-agnostic. They consume the
// {keygenParams, signParams, signCtxParams, verifyParams} structures
// below and return {keygenResult, signResult, verifyResult}. The ZAP
// dispatcher (zap_server.go) is the ONLY transport that drives these —
// the prior HTTP+JSON+hex path was removed in favour of ZAP byte-
// passthrough. One transport, one wire, one source of truth.
//
// All bytes still ride the in-process scheme contract as hex strings —
// that contract pre-dates the ZAP transport and is preserved so the
// scheme implementations are unchanged. The ZAP dispatcher decodes
// inbound raw bytes to hex strings on the scheme boundary and encodes
// scheme outputs back to raw bytes on the wire (see zap_server.go).

// keygenParams is the common shape for every <scheme>.keygen call.
type keygenParams struct {
	Threshold    int
	Participants int
}

// keygenResult is the common shape for every <scheme>.keygen response.
//
// PublicKey is a hex string by historical contract between the ZAP
// dispatcher and the scheme handlers; the ZAP wire transports the raw
// bytes (see zap_server.dispatchKeygen for the local hex decode).
type keygenResult struct {
	PublicKey string
	Shares    []string
}

// signParams is the common shape for every <scheme>.sign call.
type signParams struct {
	MessageHex string
	PubKeyHex  string
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
// is refused (gate returns ErrRefusedUnderStrictPQ which the ZAP
// dispatcher surfaces as a ZAP error message with strictPQ=true).
// Empty ChainID means "no chain context asserted"; the gate fails
// open (see profile.go::RefuseUnderStrictPQ).
type signCtxParams struct {
	MessageHex string
	PubKeyHex  string
	CtxHex     string
	ChainID    string
}

// signResult is the common shape for every <scheme>.sign response.
type signResult struct {
	SignatureHex string
}

// verifyParams is the common shape for every <scheme>.verify call.
type verifyParams struct {
	MessageHex   string
	SignatureHex string
	PubKeyHex    string
}

// verifyResult is the common shape for every <scheme>.verify response.
type verifyResult struct {
	OK bool
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
// other schemes return method-not-found on `<scheme>.sign_ctx`.
type ctxSigner interface {
	Sign_Ctx(p signCtxParams) (signResult, error)
}

// profileAwareCtxSigner is the strict-PQ-aware variant of ctxSigner.
// Schemes that implement it run the strict-PQ gate
// (RefuseUnderStrictPQ) at entry against the supplied chainID and
// resolver before producing a signature. Pulsar and magnetar
// implement this; other schemes fall back to plain ctxSigner. The
// resolver is supplied by the dispatcher (see ZapServer) so call sites
// never reach across the lock to read it. A nil resolver bypasses
// the gate (documented fail-OPEN — see profile.go).
type profileAwareCtxSigner interface {
	Sign_Ctx_Profile(p signCtxParams, resolver ChainProfileResolver) (signResult, error)
}

// schemeAliases maps deprecated scheme names to their canonical names
// for backward compatibility on the dispatcher's procedure-routing
// surface. Inbound requests using the deprecated name are silently
// routed to the canonical scheme; outbound documentation and
// responses always use the canonical name. Remove an entry once
// external callers have migrated.
//
//	"corona" → "corona"  (renamed 2026-06 per AUDIT-2026-06.md §4.3
//	                        in luxfi/corona; canonical R-LWE name).
var schemeAliases = map[string]string{
	"corona": "corona",
}

// canonicalScheme normalises an inbound scheme name through the alias
// table, returning the canonical name. Unknown names pass through
// unchanged so the caller's "unknown scheme" error path still fires.
func canonicalScheme(name string) string {
	if c, ok := schemeAliases[name]; ok {
		return c
	}
	return name
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
