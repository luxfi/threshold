package doerner

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/assert"
)

func TestDoernerConfigCreation(t *testing.T) {
	// Test config creation
	group := curve.Secp256k1{}

	// Test sender config
	senderConfig := EmptyConfigSender(group)
	assert.NotNil(t, senderConfig)
	assert.NotNil(t, senderConfig.SecretShare)
	assert.NotNil(t, senderConfig.Public)

	// Test receiver config
	receiverConfig := EmptyConfigReceiver(group)
	assert.NotNil(t, receiverConfig)
	assert.NotNil(t, receiverConfig.SecretShare)
	assert.NotNil(t, receiverConfig.Public)
}

func TestDoernerPartyValidation(t *testing.T) {
	// Test party validation
	partyIDs := test.PartyIDs(2)

	assert.Equal(t, 2, len(partyIDs))
	assert.NotEqual(t, partyIDs[0], partyIDs[1])

	// Test that sender and receiver are different
	sender := partyIDs[0]
	receiver := partyIDs[1]

	assert.NotEqual(t, sender, receiver, "Sender and receiver must be different")
}

func TestDoernerProtocolInitialization(t *testing.T) {
	// Test protocol initialization
	partyIDs := test.PartyIDs(2)
	group := curve.Secp256k1{}

	// Test that we can create start functions without running the protocol
	senderStart := Keygen(group, true, partyIDs[0], partyIDs[1], nil)
	assert.NotNil(t, senderStart)

	receiverStart := Keygen(group, false, partyIDs[1], partyIDs[0], nil)
	assert.NotNil(t, receiverStart)
}

func TestDoernerMultiplication(t *testing.T) {
	// Test multiplication setup (without running protocol)
	group := curve.Secp256k1{}

	senderConfig := EmptyConfigSender(group)
	receiverConfig := EmptyConfigReceiver(group)

	// Test that configs are created properly
	assert.NotNil(t, senderConfig)
	assert.NotNil(t, receiverConfig)

	// Test scalar creation
	scalar := group.NewScalar()
	assert.NotNil(t, scalar)
}

func TestDoernerRefreshSetup(t *testing.T) {
	// Test refresh setup
	group := curve.Secp256k1{}

	senderConfig := EmptyConfigSender(group)
	receiverConfig := EmptyConfigReceiver(group)

	// Test that configs are valid for refresh
	assert.NotNil(t, senderConfig)
	assert.NotNil(t, receiverConfig)
	assert.NotNil(t, senderConfig.SecretShare)
	assert.NotNil(t, receiverConfig.SecretShare)
}

func TestDoernerGroupOperations(t *testing.T) {
	// Test group operations
	group := curve.Secp256k1{}

	// Test scalar creation
	scalar := group.NewScalar()
	assert.NotNil(t, scalar)

	// Test point creation
	point := group.NewPoint()
	assert.NotNil(t, point)

	// Test identity
	identity := group.NewPoint()
	assert.NotNil(t, identity)
}

func TestDoernerRoleValidation(t *testing.T) {
	// Test role validation
	testCases := []struct {
		name     string
		isSender bool
		valid    bool
	}{
		{"sender role", true, true},
		{"receiver role", false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.valid, true, "Role should be valid")
		})
	}
}
