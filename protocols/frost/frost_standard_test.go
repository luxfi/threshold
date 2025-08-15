package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrostKeygenStandard(t *testing.T) {
	N := 5
	T := 3

	partyIDs := test.PartyIDs(N)

	// Run the protocol
	results, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		return frost.Keygen(curve.Secp256k1{}, id, partyIDs, T)
	})
	require.NoError(t, err)

	// Verify results
	configs := make([]*frost.Config, 0, N)
	for _, result := range results {
		config, ok := result.(*frost.Config)
		require.True(t, ok)
		require.NotNil(t, config)
		configs = append(configs, config)
	}

	// Verify all have same public key
	require.NotNil(t, configs[0].PublicKey)
	for i := 1; i < len(configs); i++ {
		require.NotNil(t, configs[i].PublicKey)
		assert.True(t, configs[0].PublicKey.Equal(configs[i].PublicKey))
	}
}
