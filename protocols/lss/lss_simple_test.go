package lss

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidation(t *testing.T) {
	group := curve.Secp256k1{}

	// Valid config
	cfg := &config.Config{
		ID:         "test",
		Group:      group,
		Threshold:  2,
		Generation: 0,
		ECDSA:      group.NewScalar(),
		Public: map[party.ID]*config.Public{
			"1": {ECDSA: group.NewPoint()},
			"2": {ECDSA: group.NewPoint()},
			"3": {ECDSA: group.NewPoint()},
		},
		ChainKey: []byte("chainkey"),
		RID:      []byte("rid"),
	}

	err := cfg.Validate()
	assert.NoError(t, err)

	// Invalid: missing group
	badCfg := &config.Config{
		ID:        "test",
		Threshold: 2,
	}
	err = badCfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing group")

	// Invalid: threshold too high
	badCfg2 := &config.Config{
		ID:        "test",
		Group:     group,
		Threshold: 5,
		ECDSA:     group.NewScalar(),
		Public: map[party.ID]*config.Public{
			"1": {ECDSA: group.NewPoint()},
			"2": {ECDSA: group.NewPoint()},
		},
		ChainKey: []byte("chainkey"),
		RID:      []byte("rid"),
	}
	err = badCfg2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threshold exceeds party count")
}

func TestConfigMarshaling(t *testing.T) {
	group := curve.Secp256k1{}

	// Create a config with proper points (not identity)
	scalar1 := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	scalar2 := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(2))

	cfg := &config.Config{
		ID:         "test",
		Group:      group,
		Threshold:  2,
		Generation: 1,
		ECDSA:      scalar1,
		Public: map[party.ID]*config.Public{
			"1": {ECDSA: scalar1.ActOnBase()},
			"2": {ECDSA: scalar2.ActOnBase()},
		},
		ChainKey: []byte("chainkey"),
		RID:      []byte("rid123456"),
	}

	// Marshal to JSON
	data, err := cfg.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal back
	cfg2 := config.EmptyConfig(group)
	err = cfg2.UnmarshalJSON(data)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, cfg.ID, cfg2.ID)
	assert.Equal(t, cfg.Threshold, cfg2.Threshold)
	assert.Equal(t, cfg.Generation, cfg2.Generation)
	assert.Equal(t, cfg.ChainKey, cfg2.ChainKey)
	assert.Equal(t, cfg.RID, cfg2.RID)
	assert.Equal(t, len(cfg.Public), len(cfg2.Public))
}

func TestPublicPointRecovery(t *testing.T) {
	group := curve.Secp256k1{}

	// Create config with enough parties
	cfg := &config.Config{
		ID:         "test",
		Group:      group,
		Threshold:  2,
		Generation: 0,
		ECDSA:      group.NewScalar(),
		Public: map[party.ID]*config.Public{
			"1": {ECDSA: group.NewPoint()},
			"2": {ECDSA: group.NewPoint()},
			"3": {ECDSA: group.NewPoint()},
		},
		ChainKey: []byte("chainkey"),
		RID:      []byte("rid"),
	}

	// Should be able to recover public point
	pubPoint, err := cfg.PublicPoint()
	require.NoError(t, err)
	require.NotNil(t, pubPoint)

	// Config with insufficient parties
	badCfg := &config.Config{
		ID:         "test",
		Group:      group,
		Threshold:  3,
		Generation: 0,
		ECDSA:      group.NewScalar(),
		Public: map[party.ID]*config.Public{
			"1": {ECDSA: group.NewPoint()},
			"2": {ECDSA: group.NewPoint()},
		},
		ChainKey: []byte("chainkey"),
		RID:      []byte("rid"),
	}

	// Should fail with insufficient parties
	_, err = badCfg.PublicPoint()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient parties")
}

func TestCompatibility(t *testing.T) {
	group := curve.Secp256k1{}

	publicShares := make(map[party.ID]*config.Public)
	publicShares["1"] = &config.Public{ECDSA: group.NewPoint()}
	publicShares["2"] = &config.Public{ECDSA: group.NewPoint()}
	publicShares["3"] = &config.Public{ECDSA: group.NewPoint()}

	c1 := &config.Config{
		ID:         "1",
		Group:      group,
		Threshold:  2,
		Generation: 1,
		ECDSA:      group.NewScalar(),
		Public:     publicShares,
		ChainKey:   []byte("chainkey1"),
		RID:        []byte("rid1"),
	}

	c2 := &config.Config{
		ID:         "2",
		Group:      group,
		Threshold:  2,
		Generation: 1,
		ECDSA:      group.NewScalar(),
		Public:     publicShares,
		ChainKey:   []byte("chainkey2"),
		RID:        []byte("rid2"),
	}

	// Same generation and public key - compatible
	assert.True(t, IsCompatibleForSigning(c1, c2))

	// Different generation - not compatible
	c2.Generation = 2
	assert.False(t, IsCompatibleForSigning(c1, c2))
}
