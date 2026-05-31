// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu re-exports github.com/luxfi/corona/gpu through the
// threshold/protocols/corona alias surface. Downstream consumers
// (luxfi/consensus) target this import path so the consensus engine
// does not depend directly on the corona module.
//
// The corona/gpu package owns ALL build-tag plumbing for the lattice
// GPU NTT dispatcher. On a pure-Go build (no cgo, no Metal, no CUDA)
// every entrypoint here is a no-op and the underlying CPU NTT path
// runs unchanged.
package gpu

import (
	"github.com/luxfi/corona/gpu"
)

// UseAccelerator opts every subsequent corona threshold signer into
// the lattice GPU NTT dispatch path. Idempotent; safe to call from
// package init or boot configuration. Returns the corona/gpu
// UseAccelerator error verbatim — currently always nil.
func UseAccelerator() error {
	return gpu.UseAccelerator()
}

// DisableAccelerator clears the opt-in flag and resets the SubRing
// dispatch threshold. Subsequent NewParams calls in the corona kernel
// leave their rings on the CPU NTT path.
func DisableAccelerator() {
	gpu.DisableAccelerator()
}

// Enabled reports whether the accelerator opt-in flag is set.
func Enabled() bool {
	return gpu.Enabled()
}

// Backend returns the active GPU backend name ("Metal", "CUDA", or a
// CPU descriptor) for diagnostic logging.
func Backend() string {
	return gpu.Backend()
}
