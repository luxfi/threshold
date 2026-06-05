// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

// zap_schema.go — ZAP wire schemas for the thresholdd byte-passthrough
// transport.
//
// ZAP is the ONLY wire transport for thresholdd; the cryptographic
// material rides as raw `[]byte` inside a fixed-layout ZAP envelope.
// No hex, no JSON, no HTTP — see doc.go for the consolidation note.
//
// Opcode allocation: this is a threshold-internal IPC wire (teleport
// TS bus → mpcd Go process); the procedure opcodes live in the
// threshold-internal kind-byte namespace. zapclient.ProcedureOpcode
// derives a stable uint16 from FNV-1a(procedureName), with the lower
// byte reserved for sub-typing under MsgType<<8. We use the canonical
// `<scheme>.<op>` procedure names so the opcode mapping is stable
// across reboots without a registry file.
//
// LP-300 status: not requested. The thresholdd surface is process-
// local IPC between teleport's TS bus and the embedding mpcd Go
// process; the wire is not cross-LP-visible. If the dispatcher's
// surface ever surfaces on the public LP-201 P2P stream layer,
// register here first per LP-300's policy.

import (
	"encoding/binary"
	"errors"
	"fmt"

	zap "github.com/luxfi/zap"
)

// Procedure names — canonical strings hashed by
// zapclient.ProcedureOpcode at registration / call time. The
// `<scheme>.<op>` shape is the canonical operator-facing name. The
// opcode emitted into the ZAP message Flags field is the FNV-1a
// digest of the procedure name; collisions are detected at
// Server.Register and force a name change at build time, never
// silent routing.
const (
	ProcCggmp21Keygen    = "cggmp21.keygen"
	ProcCggmp21Sign      = "cggmp21.sign"
	ProcCggmp21Verify    = "cggmp21.verify"
	ProcFrostKeygen      = "frost.keygen"
	ProcFrostSign        = "frost.sign"
	ProcFrostVerify      = "frost.verify"
	ProcPulsarKeygen     = "pulsar.keygen"
	ProcPulsarSign       = "pulsar.sign"
	ProcPulsarSignCtx    = "pulsar.sign_ctx"
	ProcPulsarVerify     = "pulsar.verify"
	ProcCoronaKeygen     = "corona.keygen"
	ProcCoronaSign       = "corona.sign"
	ProcCoronaVerify     = "corona.verify"
	ProcMagnetarKeygen   = "magnetar.keygen"
	ProcMagnetarSign     = "magnetar.sign"
	ProcMagnetarSignCtx  = "magnetar.sign_ctx"
	ProcMagnetarVerify   = "magnetar.verify"
	ProcBLSKeygen        = "bls.keygen"
	ProcBLSSign          = "bls.sign"
	ProcBLSVerify        = "bls.verify"
	ProcDoernerKeygen    = "doerner.keygen"
	ProcDoernerSign      = "doerner.sign"
	ProcDoernerVerify    = "doerner.verify"
)

// Fixed-payload layouts. The unsigned-integer fields and the offset
// slots for variable-length bytes/text/list payloads live at compile-
// time offsets. zap.Object accessors are zero-copy reads against the
// underlying buffer; SetBytes / SetText defer the variable-length tail
// to ObjectBuilder.Finish().
//
// Per zap/builder.go::TypeSize, a Bytes/Text/List slot is 8 bytes
// (relOffset uint32 + length uint32); a nested Object slot is 4 bytes
// (relOffset uint32). Fixed-width integers occupy their natural size.
const (
	// KeygenRequest: {Threshold uint32, Participants uint32}
	zapKeygenReqOffThreshold    = 0
	zapKeygenReqOffParticipants = 4
	zapKeygenReqSize            = 8

	// KeygenResponse: {PubKey bytes, SharesBlob bytes}
	// SharesBlob is a self-framed sequence of decimal-string share-IDs;
	// see EncodeShares / DecodeShares below.
	zapKeygenRespOffPubKey     = 0
	zapKeygenRespOffSharesBlob = 8
	zapKeygenRespSize          = 16

	// SignRequest: {Message bytes, PubKey bytes}
	zapSignReqOffMessage = 0
	zapSignReqOffPubKey  = 8
	zapSignReqSize       = 16

	// SignCtxRequest: {Message bytes, PubKey bytes, Ctx bytes, ChainID text}
	zapSignCtxReqOffMessage = 0
	zapSignCtxReqOffPubKey  = 8
	zapSignCtxReqOffCtx     = 16
	zapSignCtxReqOffChainID = 24
	zapSignCtxReqSize       = 32

	// SignResponse: {Signature bytes}
	zapSignRespOffSignature = 0
	zapSignRespSize         = 8

	// VerifyRequest: {Message bytes, Signature bytes, PubKey bytes}
	zapVerifyReqOffMessage   = 0
	zapVerifyReqOffSignature = 8
	zapVerifyReqOffPubKey    = 16
	zapVerifyReqSize         = 24

	// VerifyResponse: {OK uint8}
	zapVerifyRespOffOK = 0
	zapVerifyRespSize  = 8 // align to 8 so subsequent fields stay aligned

	// ErrorResponse: {Code int32, Message text, RefusedStrictPQ uint8}
	// Code is a JSON-RPC-style numeric error class (see ZapErrCode*
	// constants below) so callers can branch on well-defined error
	// classes. RefusedStrictPQ is the strict-PQ refusal signal — a
	// separate flag so the consumer can errors.Is(ErrRefusedUnderStrictPQ).
	zapErrRespOffCode      = 0
	zapErrRespOffMsg       = 8
	zapErrRespOffStrictPQ  = 16
	zapErrRespSize         = 24
)

// ZAP message flag layout: the upper byte carries the message kind
// (request / response / error) so dispatcher / client can route
// regardless of opcode. The opcode itself rides in the procedure-
// opcode wire (msg.Flags >> 8 by convention in zap; but zapclient
// already takes the entire uint16 as the opcode space). To stay
// compatible with zapclient's procedure-opcode-in-flags routing on
// the SERVER side (Node.Handle keyed by msgType = Flags >> 8), we
// publish the procedure opcode in the upper byte and use the lower
// byte for the request/response classification (writeCorrelated
// separately routes by reqID so this works).
//
// Concretely: outbound request flags = procOpcode | ZapKindRequest;
// the server stamps a response with flags = procOpcode |
// ZapKindResponse (or ZapKindError). Clients dispatch on the lower
// byte of the response's Flags field. The reserved bits 0x00 and 0xff
// in the procedure-opcode high byte are preserved by zapclient.
const (
	ZapKindRequest  uint8 = 0x01
	ZapKindResponse uint8 = 0x02
	ZapKindError    uint8 = 0x03
)

// ZAP error codes — JSON-RPC-style numeric classes for the documented
// error envelope. Carried in ErrorResponse.Code so callers can branch
// on well-defined error classes.
const (
	ZapErrCodeParse        = -32700
	ZapErrCodeInvalidReq   = -32600
	ZapErrCodeMethodNotFnd = -32601
	ZapErrCodeInvalidParam = -32602
	ZapErrCodeInternal     = -32000
)

// Errors surfaced by the ZAP transport.
var (
	// ErrZapMalformedRequest is returned when an inbound ZAP request
	// fails wire-validation (bad header, truncated body, missing
	// required field). Maps to ZapErrCodeInvalidReq on the response.
	ErrZapMalformedRequest = errors.New("zap: malformed request")

	// ErrZapUnknownScheme is returned when a procedure opcode does
	// not map to any registered handler. Maps to ZapErrCodeMethodNotFnd.
	ErrZapUnknownScheme = errors.New("zap: unknown scheme")

	// ErrZapUnknownProcedure is returned when a procedure opcode does
	// not map to any registered op (keygen / sign / verify / sign_ctx).
	ErrZapUnknownProcedure = errors.New("zap: unknown procedure")
)

// procOpcode returns the stable uint16 opcode the wire uses for the
// given procedure name. The opcode is FNV-1a(name) mapped into the
// upper byte (zapclient convention); colliding procedure names are
// caught at Server registration time, never at dispatch.
//
// Panics on an empty name (programmer error). Mirrors zapclient's
// MustOpcode shape; the threshold daemon's procedure set is small
// and fixed at compile time.
func procOpcode(name string) uint16 {
	if name == "" {
		panic("thresholdd: empty procedure name")
	}
	// FNV-1a 32-bit hash, upper byte 1..254, lower byte 0 (reserved
	// for the kind tag — see ZapKind* constants above). This MATCHES
	// zapclient.ProcedureOpcode so a future zapclient-backed thresholdd
	// can interop on the same wire. We don't import zapclient here to
	// avoid the mDNS dependency for a process-local IPC daemon.
	const (
		fnvOffset32 uint32 = 2166136261
		fnvPrime32  uint32 = 16777619
	)
	h := fnvOffset32
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= fnvPrime32
	}
	b := byte((h % 254) + 1)
	return uint16(b) << 8
}

// flagsForRequest stamps the outbound request flags = procOpcode | kind.
func flagsForRequest(procName string) uint16 {
	return procOpcode(procName) | uint16(ZapKindRequest)
}

// flagsForResponse mirrors the request's procedure opcode with the
// response kind. The server reads the request's flags upper byte and
// emits the matching response.
func flagsForResponse(reqFlags uint16, kind uint8) uint16 {
	return (reqFlags & 0xFF00) | uint16(kind)
}

// procFromFlags returns the procedure opcode portion of a flags word
// (upper byte). Used by the server router and the client demux.
func procFromFlags(flags uint16) uint16 {
	return flags & 0xFF00
}

// kindFromFlags returns the kind byte of a flags word (lower byte).
func kindFromFlags(flags uint16) uint8 {
	return uint8(flags & 0x00FF)
}

// EncodeShares serialises a []string of share-IDs into a self-framed
// byte slice. Layout: [uint32 count][uint32 len₁ | bytes₁]...
//
// Pulsar / Corona share-IDs are short decimal-encoded eval points
// (typically 1..6 ASCII digits); the encoding is therefore trivially
// small.
func EncodeShares(shares []string) []byte {
	totalLen := 4
	for _, s := range shares {
		totalLen += 4 + len(s)
	}
	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(shares)))
	pos := 4
	for _, s := range shares {
		binary.LittleEndian.PutUint32(out[pos:pos+4], uint32(len(s)))
		pos += 4
		copy(out[pos:pos+len(s)], s)
		pos += len(s)
	}
	return out
}

// DecodeShares is the inverse of EncodeShares. Returns an error on
// truncated input — callers MUST surface the error rather than
// silently returning a partial list.
func DecodeShares(b []byte) ([]string, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("zap shares: truncated header (have %d, need 4)", len(b))
	}
	count := binary.LittleEndian.Uint32(b[0:4])
	out := make([]string, 0, count)
	pos := uint32(4)
	for i := uint32(0); i < count; i++ {
		if pos+4 > uint32(len(b)) {
			return nil, fmt.Errorf("zap shares: truncated element %d header", i)
		}
		ln := binary.LittleEndian.Uint32(b[pos : pos+4])
		pos += 4
		if pos+ln > uint32(len(b)) {
			return nil, fmt.Errorf("zap shares: truncated element %d body (need %d, have %d)", i, ln, uint32(len(b))-pos)
		}
		out = append(out, string(b[pos:pos+ln]))
		pos += ln
	}
	return out, nil
}

// ----- KeygenRequest builder/reader -----

// buildKeygenRequest emits a ZAP message with the keygen request payload
// and request flags for the named procedure.
func buildKeygenRequest(procName string, p keygenParams) []byte {
	b := zap.NewBuilder(zap.HeaderSize + zapKeygenReqSize)
	ob := b.StartObject(zapKeygenReqSize)
	ob.SetUint32(zapKeygenReqOffThreshold, uint32(p.Threshold))
	ob.SetUint32(zapKeygenReqOffParticipants, uint32(p.Participants))
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForRequest(procName))
}

// readKeygenRequest parses a ZAP root object as a KeygenRequest.
func readKeygenRequest(msg *zap.Message) (keygenParams, error) {
	r := msg.Root()
	if r.IsNull() {
		return keygenParams{}, ErrZapMalformedRequest
	}
	return keygenParams{
		Threshold:    int(r.Uint32(zapKeygenReqOffThreshold)),
		Participants: int(r.Uint32(zapKeygenReqOffParticipants)),
	}, nil
}

// ----- KeygenResponse builder/reader -----

func buildKeygenResponse(reqFlags uint16, pubKey []byte, shares []string) []byte {
	sharesBlob := EncodeShares(shares)
	b := zap.NewBuilder(zap.HeaderSize + zapKeygenRespSize + len(pubKey) + len(sharesBlob))
	ob := b.StartObject(zapKeygenRespSize)
	ob.SetBytes(zapKeygenRespOffPubKey, pubKey)
	ob.SetBytes(zapKeygenRespOffSharesBlob, sharesBlob)
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForResponse(reqFlags, ZapKindResponse))
}

func readKeygenResponse(msg *zap.Message) ([]byte, []string, error) {
	r := msg.Root()
	if r.IsNull() {
		return nil, nil, ErrZapMalformedRequest
	}
	pubKey := r.Bytes(zapKeygenRespOffPubKey)
	sharesBlob := r.Bytes(zapKeygenRespOffSharesBlob)
	shares, err := DecodeShares(sharesBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("keygen response: %w", err)
	}
	// Return owned copies — the caller may outlive the underlying
	// message buffer when it travels through a channel or pool.
	pubKeyOut := append([]byte(nil), pubKey...)
	return pubKeyOut, shares, nil
}

// ----- SignRequest builder/reader -----

func buildSignRequest(procName string, msg, pubKey []byte) []byte {
	b := zap.NewBuilder(zap.HeaderSize + zapSignReqSize + len(msg) + len(pubKey))
	ob := b.StartObject(zapSignReqSize)
	ob.SetBytes(zapSignReqOffMessage, msg)
	ob.SetBytes(zapSignReqOffPubKey, pubKey)
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForRequest(procName))
}

func readSignRequest(m *zap.Message) ([]byte, []byte, error) {
	r := m.Root()
	if r.IsNull() {
		return nil, nil, ErrZapMalformedRequest
	}
	msg := append([]byte(nil), r.Bytes(zapSignReqOffMessage)...)
	pubKey := append([]byte(nil), r.Bytes(zapSignReqOffPubKey)...)
	return msg, pubKey, nil
}

// ----- SignCtxRequest builder/reader -----

func buildSignCtxRequest(procName string, msg, pubKey, ctx []byte, chainID string) []byte {
	b := zap.NewBuilder(zap.HeaderSize + zapSignCtxReqSize + len(msg) + len(pubKey) + len(ctx) + len(chainID))
	ob := b.StartObject(zapSignCtxReqSize)
	ob.SetBytes(zapSignCtxReqOffMessage, msg)
	ob.SetBytes(zapSignCtxReqOffPubKey, pubKey)
	ob.SetBytes(zapSignCtxReqOffCtx, ctx)
	ob.SetText(zapSignCtxReqOffChainID, chainID)
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForRequest(procName))
}

func readSignCtxRequest(m *zap.Message) (msg, pubKey, ctxBytes []byte, chainID string, err error) {
	r := m.Root()
	if r.IsNull() {
		return nil, nil, nil, "", ErrZapMalformedRequest
	}
	msg = append([]byte(nil), r.Bytes(zapSignCtxReqOffMessage)...)
	pubKey = append([]byte(nil), r.Bytes(zapSignCtxReqOffPubKey)...)
	ctxBytes = append([]byte(nil), r.Bytes(zapSignCtxReqOffCtx)...)
	chainID = r.Text(zapSignCtxReqOffChainID)
	return msg, pubKey, ctxBytes, chainID, nil
}

// ----- SignResponse builder/reader -----

func buildSignResponse(reqFlags uint16, sig []byte) []byte {
	b := zap.NewBuilder(zap.HeaderSize + zapSignRespSize + len(sig))
	ob := b.StartObject(zapSignRespSize)
	ob.SetBytes(zapSignRespOffSignature, sig)
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForResponse(reqFlags, ZapKindResponse))
}

func readSignResponse(m *zap.Message) ([]byte, error) {
	r := m.Root()
	if r.IsNull() {
		return nil, ErrZapMalformedRequest
	}
	return append([]byte(nil), r.Bytes(zapSignRespOffSignature)...), nil
}

// ----- VerifyRequest builder/reader -----

func buildVerifyRequest(procName string, msg, sig, pubKey []byte) []byte {
	b := zap.NewBuilder(zap.HeaderSize + zapVerifyReqSize + len(msg) + len(sig) + len(pubKey))
	ob := b.StartObject(zapVerifyReqSize)
	ob.SetBytes(zapVerifyReqOffMessage, msg)
	ob.SetBytes(zapVerifyReqOffSignature, sig)
	ob.SetBytes(zapVerifyReqOffPubKey, pubKey)
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForRequest(procName))
}

func readVerifyRequest(m *zap.Message) (msg, sig, pubKey []byte, err error) {
	r := m.Root()
	if r.IsNull() {
		return nil, nil, nil, ErrZapMalformedRequest
	}
	msg = append([]byte(nil), r.Bytes(zapVerifyReqOffMessage)...)
	sig = append([]byte(nil), r.Bytes(zapVerifyReqOffSignature)...)
	pubKey = append([]byte(nil), r.Bytes(zapVerifyReqOffPubKey)...)
	return msg, sig, pubKey, nil
}

// ----- VerifyResponse builder/reader -----

func buildVerifyResponse(reqFlags uint16, ok bool) []byte {
	b := zap.NewBuilder(zap.HeaderSize + zapVerifyRespSize)
	ob := b.StartObject(zapVerifyRespSize)
	ob.SetBool(zapVerifyRespOffOK, ok)
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForResponse(reqFlags, ZapKindResponse))
}

func readVerifyResponse(m *zap.Message) (bool, error) {
	r := m.Root()
	if r.IsNull() {
		return false, ErrZapMalformedRequest
	}
	return r.Bool(zapVerifyRespOffOK), nil
}

// ----- ErrorResponse builder/reader -----

// buildErrorResponse emits an error envelope with the given numeric
// code (see ZapErrCode* constants), human-readable message, and the
// strict-PQ-refusal flag. Callers branch on strictPQ first
// (errors.Is(ErrRefusedUnderStrictPQ)); otherwise the (code, msg)
// pair carries through unchanged.
func buildErrorResponse(reqFlags uint16, code int32, msg string, strictPQ bool) []byte {
	b := zap.NewBuilder(zap.HeaderSize + zapErrRespSize + len(msg))
	ob := b.StartObject(zapErrRespSize)
	ob.SetInt32(zapErrRespOffCode, code)
	ob.SetText(zapErrRespOffMsg, msg)
	if strictPQ {
		ob.SetUint8(zapErrRespOffStrictPQ, 1)
	}
	ob.FinishAsRoot()
	return b.FinishWithFlags(flagsForResponse(reqFlags, ZapKindError))
}

type zapErrorPayload struct {
	Code     int32
	Message  string
	StrictPQ bool
}

func readErrorResponse(m *zap.Message) (zapErrorPayload, error) {
	r := m.Root()
	if r.IsNull() {
		return zapErrorPayload{}, ErrZapMalformedRequest
	}
	return zapErrorPayload{
		Code:     r.Int32(zapErrRespOffCode),
		Message:  r.Text(zapErrRespOffMsg),
		StrictPQ: r.Uint8(zapErrRespOffStrictPQ) == 1,
	}, nil
}
