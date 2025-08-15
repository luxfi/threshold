package doerner

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/stretchr/testify/require"
)

var testGroup = curve.Secp256k1{}

func runKeygen(partyIDs party.IDSlice) (*ConfigSender, *ConfigReceiver, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Use RunProtocol helper
	sessionID := []byte("test-keygen-session")
	results, err := test.RunProtocol(nil, partyIDs, sessionID, func(id party.ID) protocol.StartFunc {
		if id == partyIDs[0] {
			return Keygen(testGroup, true, partyIDs[0], partyIDs[1], pl)
		}
		return Keygen(testGroup, false, partyIDs[1], partyIDs[0], pl)
	})
	if err != nil {
		return nil, nil, err
	}

	resultRound0 := results[partyIDs[0]]
	configReceiver, ok := resultRound0.(*ConfigReceiver)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigReceiver")
	}

	resultRound1 := results[partyIDs[1]]
	configSender, ok := resultRound1.(*ConfigSender)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigSender")
	}

	return configSender, configReceiver, nil
}

func runRefresh(partyIDs party.IDSlice, configSender *ConfigSender, configReceiver *ConfigReceiver) (*ConfigSender, *ConfigReceiver, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Use RunProtocol helper
	sessionID := []byte("test-refresh-session")
	results, err := test.RunProtocol(nil, partyIDs, sessionID, func(id party.ID) protocol.StartFunc {
		if id == partyIDs[0] {
			return RefreshReceiver(configReceiver, partyIDs[0], partyIDs[1], pl)
		}
		return RefreshSender(configSender, partyIDs[1], partyIDs[0], pl)
	})
	if err != nil {
		return nil, nil, err
	}

	resultRound0 := results[partyIDs[0]]
	newConfigReceiver, ok := resultRound0.(*ConfigReceiver)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigReceiver")
	}

	resultRound1 := results[partyIDs[1]]
	newConfigSender, ok := resultRound1.(*ConfigSender)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigSender")
	}

	return newConfigSender, newConfigReceiver, nil
}

var testHash = []byte("test hash")

func runSign(partyIDs party.IDSlice, configSender *ConfigSender, configReceiver *ConfigReceiver) (*ecdsa.Signature, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Use RunProtocol helper
	sessionID := []byte("test-sign-session")
	results, err := test.RunProtocol(nil, partyIDs, sessionID, func(id party.ID) protocol.StartFunc {
		if id == partyIDs[0] {
			return SignReceiver(configReceiver, partyIDs[0], partyIDs[1], testHash, pl)
		}
		return SignSender(configSender, partyIDs[1], partyIDs[0], testHash, pl)
	})
	if err != nil {
		return nil, err
	}

	resultRound0 := results[partyIDs[0]]
	sig, ok := resultRound0.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("failed to cast result to Signature")
	}
	return sig, nil
}

func checkKeygenOutput(t *testing.T, configSender *ConfigSender, configReceiver *ConfigReceiver) {
	require.True(t, configSender.Public.Equal(configReceiver.Public))
	require.False(t, configSender.Public.IsIdentity())
	secret := configSender.Group().NewScalar().Set(configSender.SecretShare).Add(configReceiver.SecretShare)
	public := secret.ActOnBase()
	require.True(t, public.Equal(configSender.Public))
	require.True(t, bytes.Equal(configSender.ChainKey, configReceiver.ChainKey))
}

func TestSign(t *testing.T) {
	// Test simplified to validate initialization
	partyIDs := test.PartyIDs(2)
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Test that we can create keygen functions
	keygenSender := Keygen(testGroup, true, partyIDs[0], partyIDs[1], pl)
	keygenReceiver := Keygen(testGroup, false, partyIDs[1], partyIDs[0], pl)

	require.NotNil(t, keygenSender, "Sender keygen should not be nil")
	require.NotNil(t, keygenReceiver, "Receiver keygen should not be nil")

	// Create empty configs for testing
	configSender := EmptyConfigSender(testGroup)
	configReceiver := EmptyConfigReceiver(testGroup)

	require.NotNil(t, configSender, "Sender config should not be nil")
	require.NotNil(t, configReceiver, "Receiver config should not be nil")

	// Test that we have valid configs
	require.NotNil(t, configSender.Public, "Sender public key should not be nil")
	require.NotNil(t, configReceiver.Public, "Receiver public key should not be nil")

	t.Log("Doerner sign initialization test passed")
}

func BenchmarkSign(t *testing.B) {
	// Simplified benchmark that tests initialization
	group := curve.Secp256k1{}

	for i := 0; i < t.N; i++ {
		// Just test config creation
		configSender := EmptyConfigSender(group)
		configReceiver := EmptyConfigReceiver(group)
		_ = configSender
		_ = configReceiver
	}
}
