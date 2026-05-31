// SPDX-License-Identifier: BSD-3-Clause
//go:build researchpreview
// +build researchpreview

package lss

import "github.com/luxfi/threshold/protocols/lss/adapters"

// createCoronaAdapter is the research-preview tag-split helper. Under
// `-tags=researchpreview` it returns the LSS-side toy Corona adapter
// (protocols/lss/adapters/corona.go) for paper-grade demonstrators.
//
// Production builds get the rejecting variant in factory_corona_prod.go
// instead, which refuses to instantiate the toy adapter and points the
// caller at luxfi/threshold/protocols/corona → luxfi/corona (the real
// Ring-LWE production primitive). See the disclosure block in
// adapters/corona.go for what makes the LSS-side adapter unsuitable
// for production.
func createCoronaAdapter() (adapters.SignerAdapter, error) {
	return adapters.NewCoronaAdapter(128, 100), nil
}
