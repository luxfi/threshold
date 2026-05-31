// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package corona

// Additional re-exports of the corona/threshold kernel that consensus
// (luxfi/consensus) consumes through the threshold/protocols/corona
// alias surface. corona.go already re-exports the round-based signing
// types (Signer, KeyShare, GroupKey, Round1Data, Round2Data, Signature)
// plus Verify / NewSigner. This file extends the surface to cover the
// fresh-keygen and batch-verification helpers.
//
// Layering: consensus imports github.com/luxfi/threshold/protocols/corona;
// this file routes those calls into github.com/luxfi/corona/threshold so
// consensus does not depend directly on the corona module. The
// underlying implementation is unchanged.

import (
	"io"

	"github.com/luxfi/corona/threshold"
)

// Params holds the ring parameters for the Corona kernel. Aliased to
// the kernel type so callers that already received a *Params from
// elsewhere (e.g. through a Signer) keep working without import
// adjustments.
type Params = threshold.Params

// NewParams constructs a fresh Params. Equivalent to threshold.NewParams.
//
// If the GPU accelerator has been opted-in via the gpu subpackage's
// UseAccelerator() call, the returned ring is registered with the
// lattice GPU dispatcher; otherwise the CPU NTT path is used. Output
// bytes are unchanged.
func NewParams() (*Params, error) {
	return threshold.NewParams()
}

// GenerateKeys runs the trusted-dealer keygen for a fresh t-of-n
// committee, returning per-party KeyShares and the persistent
// GroupKey. Equivalent to threshold.GenerateKeys.
//
// This is the fast path for in-process keygen (test harnesses,
// dispatcher seeding, off-chain ceremonies). Production chain
// consensus runs keyera.Bootstrap (Pedersen DKG, no trusted dealer)
// via the package-level Bootstrap function.
func GenerateKeys(t, n int, randSource io.Reader) ([]*KeyShare, *GroupKey, error) {
	return threshold.GenerateKeys(t, n, randSource)
}

// VerifyBatch verifies a batch of Corona threshold signatures in
// parallel. Returns a per-signature bool slice and an error only on
// argument mismatch (the per-signature verdicts live in the slice).
// Equivalent to threshold.VerifyBatch.
func VerifyBatch(groupKeys []*GroupKey, messages []string, sigs []*Signature) ([]bool, error) {
	return threshold.VerifyBatch(groupKeys, messages, sigs)
}

// VerifyBatchAll is the strict variant: returns (true, nil) iff every
// signature verifies, (false, nil) if any fails, and an error only on
// argument mismatch. Equivalent to threshold.VerifyBatchAll.
func VerifyBatchAll(groupKeys []*GroupKey, messages []string, sigs []*Signature) (bool, error) {
	return threshold.VerifyBatchAll(groupKeys, messages, sigs)
}
