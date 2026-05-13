package thresholdd

import (
	"errors"
)

// coronaScheme reserves the `corona.*` JSON-RPC namespace.
//
// Status (Red HIGH B2, 2026-05-12): the previous implementation minted
// random 32-byte tokens and stashed the live `*corona.Signature` object
// in-process. That made every "signature" returned by the dispatcher
// unverifiable by any independent party, non-durable across daemon
// restarts, and a DoS vector via unbounded map growth.
//
// `luxfi/ringtail/threshold.Signature` is a struct of ring polynomials
// (`C ring.Poly`, `Z structs.Vector[ring.Poly]`, `Delta
// structs.Vector[ring.Poly]`). The lattice library exposes
// `MarshalBinary` / `UnmarshalBinary` on those underlying types, but
// composing them into a single canonical wire format — the form
// independent peers and L1 verifier contracts actually consume — is a
// primitive-layer change in `luxfi/ringtail`, not a dispatcher concern.
// `corona.Verify(*GroupKey, string, *Signature)` also takes the live
// object rather than bytes.
//
// Until `luxfi/ringtail/threshold` ships:
//
//	func (Signature) MarshalBinary() ([]byte, error)
//	func (*Signature) UnmarshalBinary([]byte) error
//	func VerifyBytes(gkBytes, msg, sigBytes []byte) bool
//
// the dispatcher refuses every op with an explicit error. Same shape
// as `doernerScheme`. The wire slot stays reserved so the teleport/mpc
// bus and any other client keeps a stable route plan.
type coronaScheme struct{}

func newCoronaScheme() *coronaScheme { return &coronaScheme{} }

// errCoronaNotImplemented is returned for every Corona op until
// luxfi/ringtail/threshold ships stable wire encodings for Signature
// and GroupKey. See corona.go header for the contract.
var errCoronaNotImplemented = errors.New(
	"corona: not yet implemented — luxfi/ringtail/threshold.Signature/GroupKey " +
		"lack stable wire encodings (MarshalBinary/UnmarshalBinary + stateless " +
		"VerifyBytes). The dispatcher refuses to mint in-process tokens that no " +
		"second party can verify (Red HIGH B2). Fix upstream and remove this guard.",
)

func (s *coronaScheme) Keygen(p keygenParams) (keygenResult, error) {
	return keygenResult{}, errCoronaNotImplemented
}

func (s *coronaScheme) Sign(p signParams) (signResult, error) {
	return signResult{}, errCoronaNotImplemented
}

func (s *coronaScheme) Verify(p verifyParams) (verifyResult, error) {
	return verifyResult{}, errCoronaNotImplemented
}
