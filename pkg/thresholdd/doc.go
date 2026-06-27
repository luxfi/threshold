// Package thresholdd is the ZAP-native dispatcher that exposes every
// luxfi/threshold protocol (cggmp21, frost, pulsar, corona, magnetar,
// doerner) on a single byte-passthrough transport.
//
// One wire, one transport: the historical HTTP+JSON+hex path was
// removed in favour of ZAP byte-passthrough. There is no JSON-RPC
// fallback, no `--http` flag, no deprecation shim. Pre-cutover
// JSON-RPC clients fail to connect — that is the documented behaviour.
//
// The same dispatcher is started by both:
//
//   - The standalone thresholdd binary (cmd/thresholdd/main.go) used
//     for development and CI; and
//   - luxfi/mpc's production daemon mpcd, which embeds the dispatcher
//     as a sub-listener so a single MPC process owns every threshold
//     scheme it speaks.
//
// Wire shape (see zap_schema.go for the field offsets):
//
//	ZAP message with procedure opcode in msg.Flags upper byte;
//	message kind (request/response/error) in the lower byte.
//
// Procedures (per scheme):
//
//	<scheme>.keygen   { Threshold, Participants }
//	                  -> { PublicKey, Shares }   (all bytes)
//	<scheme>.sign     { Message, PubKey }
//	                  -> { Signature }
//	<scheme>.verify   { Message, Signature, PubKey }
//	                  -> { OK }
//
// Pulsar and magnetar additionally expose:
//
//	<scheme>.sign_ctx { Message, PubKey, Ctx, ChainID }
//	                  -> { Signature }
//
// where Ctx is the FIPS-204 §5.2 / FIPS-205 §10.2 context octet
// string (raw bytes; empty binds the empty ctx). Signatures emitted
// via sign_ctx satisfy the on-chain EVM precompile's domain-
// separation contract (`lux-evm-precompile-mldsa-v1` /
// `lux-evm-precompile-slhdsa-v1`) — verifiable by passing the same
// ctx to luxfi/precompile/{mldsa,slhdsa}.VerifySignatureCtx, or by
// any FIPS-204/205 verifier with ctx-binding support.
//
// Decomplecting note: this package contains zero ROUTING policy.
// Per-method admission, auth, audit, and rate limiting belong on
// the caller side (mpcd's API surface, or the teleport bus).
//
// Strict-PQ profile gate (profile.go):
//
//	The dispatcher DOES carry one narrow piece of policy: the
//	strict-PQ refusal gate on Sign_Ctx. This is NOT routing —
//	it is a primitive-soundness guard tightly coupled to the
//	pulsar v0.3 dealer shortcut (and the magnetar single-
//	validator shortcut) that the dispatcher's Sign_Ctx path
//	uses today. Refusing those under strict-PQ has to happen at
//	the call site that produces the signature, not at an outer
//	routing layer that does not know which signing path the
//	dispatcher chose. The gate is ONE function in ONE place:
//	profile.go::RefuseUnderStrictPQ.
//
//	Strict-PQ profile semantics:
//
//	  - Strict-PQ profile (ProfileID 0x01 or 0x03 in
//	    luxfi/consensus/config terms): NO single-party dealer
//	    shortcuts ANYWHERE on the dispatcher. Sign_Ctx refuses
//	    with a ZAP ErrorResponse carrying strictPQ=true (callers
//	    branch via errors.Is(ErrRefusedUnderStrictPQ)) until the
//	    underlying primitive is swapped to a proper threshold
//	    ctx-bound path (pulsar v0.4 OrchestrateV03SignCtx;
//	    magnetar aggregate cert with ctx).
//	  - Legacy-compat profile (everything else): dealer shortcuts
//	    are acceptable as documented dev-tooling. Operators are
//	    responsible for not building production on top of
//	    permissive profiles.
//
//	Chain-profile lookup is supplied by the embedder via the
//	ChainProfileResolver interface (no upward dep on
//	luxfi/consensus/config). The standalone thresholdd CLI
//	leaves the resolver unwired (gate fails open — dev tooling);
//	luxfi/mpc / luxfi/node wire an adapter that calls
//	config.ProfileByID under the hood.
//
//	When sister-agent's pulsar v0.4 / magnetar aggregate-cert
//	ctx-bound paths land, the dispatcher's Sign_Ctx swaps to
//	those — the gate then becomes dead code on those call sites
//	and the chain-ID-based refusal vanishes. profile.go and
//	the gate function stay as the documented audit hook for any
//	future primitive-soundness gate on strict-PQ chains.
package thresholdd
