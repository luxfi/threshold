// SPDX-License-Identifier: BSD-3-Clause
//go:build researchpreview
// +build researchpreview

// External (adapters_test package) tests for the LSS-side toy Corona
// adapter. Build with -tags=researchpreview only — the adapter itself
// ships under the same gate. Production builds: route post-quantum
// threshold through luxfi/threshold/protocols/corona.
//
// The "Corona" naming in the LSS path is a chain-identifier collision
// with the real luxfi/corona primitive; this file's tests assert the
// shape of the LSS-side toy, NOT cryptographic soundness. See the
// disclosure block in corona.go for the trust-model statement.
package adapters_test

import (
	"fmt"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoronaPQAdapter exercises the LSS-side Corona adapter surface
// for shape under the researchpreview gate. Does NOT assert
// cryptographic soundness — the adapter is paper-grade only.
func TestCoronaPQAdapter(t *testing.T) {
	t.Run("SecurityLevels", func(t *testing.T) {
		levels := []int{128, 192, 256}

		for _, level := range levels {
			corona := adapters.NewCoronaAdapter(level, 100)

			parties := []party.ID{"alice", "bob", "charlie"}
			pubKey, shares, err := corona.CoronaDKG(parties, 2)
			require.NoError(t, err)
			assert.NotNil(t, pubKey)
			assert.Len(t, shares, 3)
		}
	})

	t.Run("OfflinePreprocessing", func(t *testing.T) {
		corona := adapters.NewCoronaAdapter(128, 10)

		parties := []party.ID{"alice", "bob", "charlie"}
		_, _, err := corona.CoronaDKG(parties, 2)
		require.NoError(t, err)

		err = corona.PreprocessOffline(5)
		require.NoError(t, err)

		message := []byte("test message")
		digest, _ := corona.Digest(message)

		mockScalar := curve.Secp256k1{}.NewScalar()
		share := adapters.Share{
			ID:    parties[0],
			Value: mockScalar,
		}

		partial, err := corona.SignEC(digest, share)
		require.NoError(t, err)
		assert.NotNil(t, partial)
	})

	t.Run("LargeScale", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping large scale test in short mode")
		}

		corona := adapters.NewCoronaAdapter(128, 100)

		parties := make([]party.ID, 100)
		for i := 0; i < 100; i++ {
			parties[i] = party.ID(fmt.Sprintf("party_%d", i))
		}

		_, shares, err := corona.CoronaDKG(parties, 67)
		require.NoError(t, err)
		assert.Len(t, shares, 100)
	})

	t.Run("SignatureSize", func(t *testing.T) {
		corona := adapters.NewCoronaAdapter(128, 10)

		params := adapters.GetRecommendedParams(128, 10)
		assert.Equal(t, 13400, params.SignatureSize)

		fullSig := &adapters.CoronaFullSig{
			Signature: make([]int64, params.N),
			Size:      params.SignatureSize,
		}

		encoded, err := corona.Encode(fullSig)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(encoded), params.SignatureSize)
	})
}
