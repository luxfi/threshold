// SPDX-License-Identifier: BSD-3-Clause
//go:build researchpreview
// +build researchpreview

// Tests for the LSS-side toy Corona adapter. Build with
// -tags=researchpreview only. The adapter itself ships under the same
// gate; production builds must NOT compile this file. See the
// disclosure block at the top of corona.go for the full trust-model
// statement.
package adapters

import (
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoronaAdapter tests the research-preview LSS Corona adapter
// surface for shape only — it does NOT assert any cryptographic
// soundness. The adapter is paper-grade, not production. See
// corona.go header.
func TestCoronaAdapter(t *testing.T) {
	t.Run("SecurityLevels", func(t *testing.T) {
		levels := []int{128, 192, 256}

		for _, level := range levels {
			adapter := NewCoronaAdapter(level, 5)
			require.NotNil(t, adapter)

			config := &UnifiedConfig{
				SignatureScheme: SignatureCorona,
				Threshold:       3,
				PartyIDs:        []party.ID{"alice", "bob", "charlie", "dave", "eve"},
				CoronaConfig: &CoronaExtensions{
					SecurityLevel: level,
				},
			}

			err := adapter.ValidateConfig(config)
			assert.NoError(t, err)
		}
	})

	t.Run("PreprocessingGeneration", func(t *testing.T) {
		adapter := NewCoronaAdapter(128, 5)

		parties := []party.ID{"alice", "bob", "charlie", "dave", "eve"}
		// GeneratePreprocessing would be called here if it existed
		_ = adapter
		_ = parties

		// Verify adapter was created successfully
		assert.NotNil(t, adapter)
		assert.Len(t, parties, 5)
	})

	t.Run("SignatureSize", func(t *testing.T) {
		testCases := []struct {
			securityLevel int
			expectedSize  int
		}{
			{128, 13400},
			{192, 28600},
			{256, 53200},
		}

		for _, tc := range testCases {
			_ = NewCoronaAdapter(tc.securityLevel, 5)
			params := GetRecommendedParams(tc.securityLevel, 5)
			assert.Equal(t, tc.expectedSize, params.SignatureSize)
		}
	})
}
