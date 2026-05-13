// Package thresholdd is the JSON-RPC 2.0 dispatcher that exposes every
// luxfi/threshold protocol (cggmp21, frost, pulsar, corona, bls,
// doerner) on a single process-local HTTP endpoint.
//
// The same dispatcher is started by both:
//
//   - The standalone thresholdd binary (cmd/thresholdd/main.go) used
//     for development and CI; and
//   - luxfi/mpc's production daemon mpcd, which embeds the dispatcher
//     as a sub-listener so a single MPC process owns every threshold
//     scheme it speaks.
//
// Wire format mirrors the teleport mpc bus (mpc/src/signers/rpc.ts):
//
//	POST / with body
//	  {"jsonrpc":"2.0","id":N,"method":"<scheme>.<op>","params":{...}}
//
// Methods (per scheme):
//
//	<scheme>.keygen { threshold, participants }
//	                -> { publicKey: hex, shares: [hex, ...] }
//	<scheme>.sign   { messageHex, pubKeyHex }
//	                -> { signatureHex }
//	<scheme>.verify { messageHex, signatureHex, pubKeyHex }
//	                -> { ok: bool }
//
// Decomplecting note: this package contains zero policy. Profile
// gating, auth, audit, and any per-scheme admission rules belong on
// the caller side (mpcd's API surface, or the teleport bus).
package thresholdd
