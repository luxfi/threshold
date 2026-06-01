package test

import (
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// CreateMockLSSConfigs creates mock LSS configs for testing
func CreateMockLSSConfigs(partyIDs []party.ID, threshold int) []*config.Config {
	configs := make([]*config.Config, len(partyIDs))
	group := curve.Secp256k1{}

	for i, id := range partyIDs {
		configs[i] = &config.Config{
			ID:        id,
			Threshold: threshold,
			Group:     group,
			ECDSA:     group.NewScalar(),
			ChainKey:  []byte("mock-chain-key"),
			RID:       []byte("mock-rid"),
			Public:    make(map[party.ID]*config.Public),
		}

		// Add public keys for all parties
		for _, pid := range partyIDs {
			configs[i].Public[pid] = &config.Public{
				ECDSA: group.NewPoint(),
			}
		}
	}

	return configs
}

// CreateMockFROSTConfigs creates mock FROST configs for testing
func CreateMockFROSTConfigs(partyIDs []party.ID, threshold int) []interface{} {
	configs := make([]interface{}, len(partyIDs))
	group := curve.Secp256k1{}

	for i, id := range partyIDs {
		// Create a mock config that satisfies FROST requirements
		configs[i] = struct {
			ID           party.ID
			Threshold    int
			Group        curve.Curve
			PublicKey    curve.Point
			SecretShare  curve.Scalar
			PublicShares map[party.ID]curve.Point
		}{
			ID:           id,
			Threshold:    threshold,
			Group:        group,
			PublicKey:    group.NewPoint(),
			SecretShare:  group.NewScalar(),
			PublicShares: make(map[party.ID]curve.Point),
		}
	}

	return configs
}

// CreateMockCMPConfigs creates mock CMP configs for testing
func CreateMockCMPConfigs(partyIDs []party.ID, threshold int) []interface{} {
	configs := make([]interface{}, len(partyIDs))
	group := curve.Secp256k1{}

	for i, id := range partyIDs {
		// Create a mock config that satisfies CMP requirements
		configs[i] = struct {
			ID        party.ID
			Threshold int
			Group     curve.Curve
			PublicKey curve.Point
			Share     curve.Scalar
			Nonce     []byte
		}{
			ID:        id,
			Threshold: threshold,
			Group:     group,
			PublicKey: group.NewPoint(),
			Share:     group.NewScalar(),
			Nonce:     []byte("mock-nonce"),
		}
	}

	return configs
}
