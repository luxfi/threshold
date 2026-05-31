// SPDX-License-Identifier: BSD-3-Clause
//go:build !researchpreview
// +build !researchpreview

package lss

import (
	"errors"

	"github.com/luxfi/threshold/protocols/lss/adapters"
)

// createCoronaAdapter is the production tag-split helper. It refuses to
// build a CoronaAdapter on the LSS path and points callers at the real
// post-quantum threshold primitive at luxfi/threshold/protocols/corona
// (which itself wraps luxfi/corona — Ring-LWE with Pedersen-DKG,
// canonical wire codec, dudect-validated CT hot paths).
//
// The LSS-side adapter (protocols/lss/adapters/corona.go) is paper-grade
// only: textbook-LWE additive "DKG" without Lagrange threshold sharing,
// Q=12289 (< 2^14), Box-Muller-from-uniform Gaussian sampler that is
// not constant-time. The naming collision with the real Corona primitive
// is what made this a Production Routing Risk — `lss.NewLSS(lss.Corona,
// ...)` would silently return the toy adapter on production builds.
//
// To use the research-preview LSS adapter for paper reproducibility,
// build with `-tags=researchpreview`.
func createCoronaAdapter() (adapters.SignerAdapter, error) {
	return nil, errors.New(
		"lss: production builds refuse to instantiate the LSS Corona adapter " +
			"— route post-quantum threshold signing through " +
			"luxfi/threshold/protocols/corona (which wraps the production " +
			"luxfi/corona Ring-LWE primitive). The LSS-side adapter at " +
			"protocols/lss/adapters/corona.go is research-preview only and " +
			"lives behind -tags=researchpreview. See the file header for the " +
			"trust-model disclosure.",
	)
}
