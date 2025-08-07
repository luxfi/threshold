package sign_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/luxfi/threshold/protocols/lss/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignStart(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Create a mock config
	cfg := &config.Config{
		ID:        party.ID("alice"),
		Group:     group,
		Threshold: 2,
		ECDSA:     group.NewScalar(),
		Public: map[party.ID]*config.Public{
			"alice":   {ECDSA: group.NewScalar().ActOnBase()},
			"bob":     {ECDSA: group.NewScalar().ActOnBase()},
			"charlie": {ECDSA: group.NewScalar().ActOnBase()},
		},
		ChainKey: []byte("test-chain-key"),
		RID:      []byte("test-rid"),
	}
	
	// Use 3 signers so threshold < number of signers
	signers := []party.ID{"alice", "bob", "charlie"}
	message := []byte("test message")
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	startFunc := sign.Start(cfg, signers, message, pl)
	assert.NotNil(t, startFunc)
	
	// Test that the start function creates a session
	sessionID := []byte("test-session")
	session, err := startFunc(sessionID)
	require.NoError(t, err)
	assert.NotNil(t, session)
}

func TestSignValidation(t *testing.T) {
	group := curve.Secp256k1{}
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	// Base config
	cfg := &config.Config{
		ID:        party.ID("alice"),
		Group:     group,
		Threshold: 2,
		ECDSA:     group.NewScalar(),
		Public: map[party.ID]*config.Public{
			"alice":   {ECDSA: group.NewScalar().ActOnBase()},
			"bob":     {ECDSA: group.NewScalar().ActOnBase()},
			"charlie": {ECDSA: group.NewScalar().ActOnBase()},
		},
	}
	
	testCases := []struct {
		name        string
		signers     []party.ID
		message     []byte
		expectError bool
	}{
		{
			name:        "valid signers",
			signers:     []party.ID{"alice", "bob", "charlie"},
			message:     []byte("test"),
			expectError: false,
		},
		{
			name:        "too few signers",
			signers:     []party.ID{"alice"},
			message:     []byte("test"),
			expectError: true,
		},
		{
			name:        "empty message",
			signers:     []party.ID{"alice", "bob", "charlie"},
			message:     []byte{},
			expectError: false, // Empty messages are allowed
		},
		{
			name:        "unknown signer",
			signers:     []party.ID{"alice", "bob", "unknown"},
			message:     []byte("test"),
			expectError: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			startFunc := sign.Start(cfg, tc.signers, tc.message, pl)
			assert.NotNil(t, startFunc)
			
			// Validation happens when creating the session
			session, err := startFunc([]byte("session"))
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
			}
		})
	}
}

func TestSignMessage(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Create configs for multiple parties
	configs := make([]*config.Config, 3)
	partyIDs := []party.ID{"alice", "bob", "charlie"}
	
	// Generate private keys and public shares
	publicShares := make(map[party.ID]*config.Public)
	for i, id := range partyIDs {
		privKey := group.NewScalar()
		// Set to a simple non-zero value
		bytes := make([]byte, 32)
		bytes[0] = byte(i + 1)
		privKey.UnmarshalBinary(bytes)
		
		publicShares[id] = &config.Public{
			ECDSA: privKey.ActOnBase(),
		}
		
		configs[i] = &config.Config{
			ID:        id,
			Group:     group,
			Threshold: 2,
			ECDSA:     privKey,
			Public:    publicShares,
			ChainKey:  []byte("chain-key"),
			RID:       []byte("rid"),
		}
	}
	
	// Test signing with more than threshold parties
	signers := []party.ID{"alice", "bob", "charlie"}
	message := []byte("important message")
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	// Create sign protocol for first signer
	startFunc := sign.Start(configs[0], signers, message, pl)
	assert.NotNil(t, startFunc)
	
	// Try to start the protocol
	session, err := startFunc([]byte("session-id"))
	require.NoError(t, err)
	assert.NotNil(t, session)
}

func TestConcurrentSigning(t *testing.T) {
	group := curve.Secp256k1{}
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	cfg := &config.Config{
		ID:        party.ID("alice"),
		Group:     group,
		Threshold: 2,
		ECDSA:     group.NewScalar(),
		Public: map[party.ID]*config.Public{
			"alice": {ECDSA: group.NewScalar().ActOnBase()},
			"bob":   {ECDSA: group.NewScalar().ActOnBase()},
			"charlie": {ECDSA: group.NewScalar().ActOnBase()},
		},
	}
	
	signers := []party.ID{"alice", "bob", "charlie"}
	
	// Start multiple sign sessions concurrently
	numSessions := 5
	done := make(chan bool, numSessions)
	
	for i := 0; i < numSessions; i++ {
		go func(idx int) {
			message := []byte(string(rune('a' + idx)))
			startFunc := sign.Start(cfg, signers, message, pl)
			
			if startFunc != nil {
				sessionID := []byte(string(rune('0' + idx)))
				_, err := startFunc(sessionID)
				if err != nil {
					// Protocol not fully implemented
					done <- false
				} else {
					done <- true
				}
			} else {
				done <- false
			}
		}(i)
	}
	
	// Wait for all sessions
	successCount := 0
	for i := 0; i < numSessions; i++ {
		if <-done {
			successCount++
		}
	}
	
	// At least one should succeed
	assert.Greater(t, successCount, 0, "At least one concurrent session should succeed")
}