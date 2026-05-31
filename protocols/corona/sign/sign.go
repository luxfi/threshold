// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package sign re-exports parameters from github.com/luxfi/corona/sign
// through the threshold/protocols/corona alias surface. Downstream
// consumers (luxfi/consensus) target this import path so the consensus
// engine does not depend directly on the corona module.
//
// Only the public ring parameter Q is re-exported here. The full sign
// kernel (Party / Gen / round-1/-2 helpers) is an internal of the
// corona/threshold package and should not be reached around the alias.
package sign

import (
	"github.com/luxfi/corona/sign"
)

// Q is the 48-bit NTT-friendly prime that defines the Corona signing
// ring modulus. Aliased to sign.Q. The value is fixed at
// 0x1000000004A01; the alias exists so consensus does not import the
// corona module directly when it only needs the modulus constant for
// local arithmetic (e.g. Lambda recomputation).
const Q = sign.Q
