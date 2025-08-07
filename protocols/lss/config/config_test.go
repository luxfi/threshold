package config_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigCreation(t *testing.T) {
	group := curve.Secp256k1{}
	id := party.ID("test")
	threshold := 3
	
	cfg := &config.Config{
		ID:        id,
		Group:     group,
		Threshold: threshold,
		ECDSA:     group.NewScalar(),
		Public:    make(map[party.ID]*config.Public),
		ChainKey:  []byte("chainkey"),
		RID:       []byte("rid"),
	}
	
	assert.Equal(t, id, cfg.ID)
	assert.Equal(t, threshold, cfg.Threshold)
	assert.NotNil(t, cfg.ECDSA)
}

func TestConfigValidation(t *testing.T) {
	group := curve.Secp256k1{}
	
	testCases := []struct {
		name      string
		config    *config.Config
		expectErr bool
	}{
		{
			name: "valid config",
			config: &config.Config{
				ID:        party.ID("test"),
				Group:     group,
				Threshold: 2,
				ECDSA:     group.NewScalar(),
				Public: map[party.ID]*config.Public{
					"p1": {ECDSA: group.NewScalar().ActOnBase()},
					"p2": {ECDSA: group.NewScalar().ActOnBase()},
					"p3": {ECDSA: group.NewScalar().ActOnBase()},
				},
				ChainKey: []byte("test-chain-key"),
				RID:      []byte("test-rid"),
			},
			expectErr: false,
		},
		{
			name: "invalid threshold",
			config: &config.Config{
				ID:        party.ID("test"),
				Group:     group,
				Threshold: 0,
				ECDSA:     group.NewScalar(),
				Public:    make(map[party.ID]*config.Public),
			},
			expectErr: true,
		},
		{
			name: "nil private share",
			config: &config.Config{
				ID:        party.ID("test"),
				Group:     group,
				Threshold: 2,
				ECDSA:     nil,
				Public:    make(map[party.ID]*config.Public),
			},
			expectErr: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPublicKeyRecovery(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Create shares
	shares := make(map[party.ID]*config.Public)
	for i := 1; i <= 3; i++ {
		scalar := group.NewScalar()
		// Set to a simple non-zero value
		bytes := make([]byte, 32)
		bytes[0] = byte(i)
		scalar.UnmarshalBinary(bytes)
		shares[party.ID(string(rune('0'+i)))] = &config.Public{
			ECDSA: scalar.ActOnBase(),
		}
	}
	
	cfg := &config.Config{
		ID:        party.ID("1"),
		Group:     group,
		Threshold: 2,
		ECDSA:     group.NewScalar(),
		Public:    shares,
	}
	
	pubKey, err := cfg.PublicKey()
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

func TestPartyIDs(t *testing.T) {
	shares := make(map[party.ID]*config.Public)
	shares["alice"] = &config.Public{}
	shares["bob"] = &config.Public{}
	shares["charlie"] = &config.Public{}
	
	cfg := &config.Config{
		Public: shares,
	}
	
	ids := cfg.PartyIDs()
	assert.Len(t, ids, 3)
	
	// Check all IDs are present
	idMap := make(map[party.ID]bool)
	for _, id := range ids {
		idMap[id] = true
	}
	assert.True(t, idMap["alice"])
	assert.True(t, idMap["bob"])
	assert.True(t, idMap["charlie"])
}