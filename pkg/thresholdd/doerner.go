package thresholdd

import (
	"errors"
)

// doernerScheme exposes the Doerner 2-of-2 ECDSA namespace.
//
// Status: the round-protocol path in luxfi/threshold/protocols/doerner
// is non-functional end-to-end as of this commit. The upstream tests
// only exercise initialization (TestSign in doerner_test.go logs
// "Doerner sign initialization test passed" without ever calling
// runKeygen). Driving the protocol through the canonical harness
// surfaces "message contained empty fields" during round 0 and aborts.
//
// Rather than ship a stub that pretends to work, the daemon returns an
// explicit error for every Doerner op. The wire surface remains
// reserved so the daemon stays orthogonal and the TS bus can route to
// it once the upstream is fixed.
type doernerScheme struct{}

func newDoernerScheme() *doernerScheme { return &doernerScheme{} }

// errDoernerBroken is returned for every Doerner op until the upstream
// round-protocol is fixed. See doerner.go header for details.
var errDoernerBroken = errors.New(
	"doerner: round-protocol non-functional in luxfi/threshold/protocols/doerner " +
		"(aborts in round 0 with 'message contained empty fields'); the wire surface " +
		"is reserved — fix the protocol upstream and remove this guard",
)

func (s *doernerScheme) Keygen(p keygenParams) (keygenResult, error) {
	return keygenResult{}, errDoernerBroken
}

func (s *doernerScheme) Sign(p signParams) (signResult, error) {
	return signResult{}, errDoernerBroken
}

func (s *doernerScheme) Verify(p verifyParams) (verifyResult, error) {
	return verifyResult{}, errDoernerBroken
}
