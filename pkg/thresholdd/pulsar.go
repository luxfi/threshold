package thresholdd

import (
	"errors"
)

// pulsarScheme reserves the `pulsar.*` JSON-RPC namespace.
//
// Status (Red HIGH B2, 2026-05-12): the previous implementation minted
// random 32-byte tokens and stashed the live `*pulsar.Signature` object
// in-process. That made every "signature" returned by the dispatcher
// unverifiable by any independent party (other mpcd, bridge node, L1
// contract), non-durable across daemon restarts, and a DoS vector via
// unbounded map growth. The threshold-bus contract requires that
// `<scheme>.sign` → `signatureHex` returns the canonical signature
// bytes that the underlying primitive's stateless `Verify` accepts.
//
// `luxfi/corona/threshold.Signature` is a struct of ring polynomials
// (`C ring.Poly`, `Z structs.Vector[ring.Poly]`, `Delta
// structs.Vector[ring.Poly]`). The lattice library exposes
// `MarshalBinary` / `UnmarshalBinary` on those underlying types, but
// composing them into a single canonical FIPS-204-aggregate-equivalent
// wire format — the form L1 verifier contracts and independent peers
// actually consume — is a primitive-layer change in `luxfi/corona`,
// not a dispatcher concern. `pulsar.Verify(*GroupKey, string,
// *Signature)` also takes the live object rather than bytes.
//
// Until `luxfi/corona/threshold` ships:
//
//	func (Signature) MarshalBinary() ([]byte, error)
//	func (*Signature) UnmarshalBinary([]byte) error
//	func VerifyBytes(gkBytes, msg, sigBytes []byte) bool
//
// (i.e. signatures + group keys round-trippable across processes /
// chains), the dispatcher refuses every op with an explicit error.
// Same shape as `doernerScheme`. The wire slot stays reserved so the
// teleport/mpc bus and any other client keeps a stable route plan.
type pulsarScheme struct{}

func newPulsarScheme() *pulsarScheme { return &pulsarScheme{} }

// errPulsarNotImplemented is returned for every Pulsar op until
// luxfi/corona/threshold ships stable wire encodings for Signature
// and GroupKey. See pulsar.go header for the contract.
var errPulsarNotImplemented = errors.New(
	"pulsar: not yet implemented — luxfi/corona/threshold.Signature/GroupKey " +
		"lack stable wire encodings (MarshalBinary/UnmarshalBinary + stateless " +
		"VerifyBytes). The dispatcher refuses to mint in-process tokens that no " +
		"second party can verify (Red HIGH B2). Fix upstream and remove this guard.",
)

func (s *pulsarScheme) Keygen(p keygenParams) (keygenResult, error) {
	return keygenResult{}, errPulsarNotImplemented
}

func (s *pulsarScheme) Sign(p signParams) (signResult, error) {
	return signResult{}, errPulsarNotImplemented
}

func (s *pulsarScheme) Verify(p verifyParams) (verifyResult, error) {
	return verifyResult{}, errPulsarNotImplemented
}
