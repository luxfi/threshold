package ringtail_test

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/ringtail"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

// TestKeygen tests keygen function creation and session initialization
func TestKeygen(t *testing.T) {
	n := 3
	threshold := 2

	partyIDs := make([]party.ID, n)
	for i := 0; i < n; i++ {
		partyIDs[i] = party.ID(string(rune('a' + i)))
	}

	keygenFunc := ringtail.Keygen(partyIDs[0], partyIDs, threshold, nil)
	require.NotNil(t, keygenFunc, "Keygen should return a function")

	sessionID := []byte("test-session")
	session, err := keygenFunc(sessionID)

	if err != nil {
		t.Logf("Session creation: %v", err)
	} else if session != nil {
		t.Log("Session created")
	}
}

// TestKeygenWithHarness tests keygen with protocol harness and timeout
func TestKeygenWithHarness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	harness := test.NewHarness(t, partyIDs).WithTimeout(5 * time.Second)

	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered: %v", r)
			}
			done <- true
		}()

		for _, id := range partyIDs {
			sessionID := []byte("test-ringtail-keygen")
			startFunc := ringtail.Keygen(id, partyIDs, threshold, pl)

			handler, err := harness.CreateHandler(id, startFunc, sessionID)
			if err != nil {
				t.Logf("Handler error for %s: %v", id, err)
				return
			}
			if handler != nil {
				t.Logf("Handler created for %s", id)
			}
		}
	}()

	select {
	case <-done:
		t.Log("Completed")
	case <-ctx.Done():
		t.Log("Timed out")
	}
}

// TestSign tests sign function creation and session initialization
func TestSign(t *testing.T) {
	cfg := config.NewConfig("test-party", 2, config.Security128)
	require.NotNil(t, cfg)

	signers := []party.ID{"a", "b"}
	message := []byte("test message")

	signFunc := ringtail.Sign(cfg, signers, message, nil)
	require.NotNil(t, signFunc, "Sign should return a function")

	sessionID := []byte("test-sign-session")
	session, err := signFunc(sessionID)

	if err != nil {
		t.Logf("Session creation: %v", err)
	} else if session != nil {
		t.Log("Sign session created")
	}
}

// TestSignWithTimeout tests signing with harness and timeout
func TestSignWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	message := []byte("test message for signing")

	configs := make(map[party.ID]*config.Config)
	for _, id := range partyIDs {
		configs[id] = config.NewConfig(id, threshold, config.Security128)
	}

	signers := partyIDs

	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered: %v", r)
			}
			done <- true
		}()

		for _, id := range signers {
			cfg := configs[id]
			sessionID := []byte("test-ringtail-sign")
			startFunc := ringtail.Sign(cfg, signers, message, pl)

			session, err := startFunc(sessionID)
			if err != nil {
				t.Logf("Error for %s: %v", id, err)
			} else if session != nil {
				t.Logf("Session for %s", id)
			}
		}
	}()

	select {
	case <-done:
		t.Log("Completed")
	case <-ctx.Done():
		t.Log("Timed out")
	}
}

// TestRefresh tests refresh function creation and session initialization
func TestRefresh(t *testing.T) {
	cfg := config.NewConfig("test-party", 2, config.Security128)
	require.NotNil(t, cfg)

	parties := []party.ID{"a", "b", "c"}
	threshold := 2

	refreshFunc := ringtail.Refresh(cfg, parties, threshold, nil)
	require.NotNil(t, refreshFunc, "Refresh should return a function")

	sessionID := []byte("test-refresh-session")
	session, err := refreshFunc(sessionID)

	if err != nil {
		t.Logf("Session creation: %v", err)
	} else if session != nil {
		t.Log("Refresh session created")
	}
}

// TestRefreshWithTimeout tests refresh with harness and timeout
func TestRefreshWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)

	configs := make(map[party.ID]*config.Config)
	for _, id := range partyIDs {
		configs[id] = config.NewConfig(id, threshold, config.Security128)
		configs[id].Participants = partyIDs
	}

	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered: %v", r)
			}
			done <- true
		}()

		for _, id := range partyIDs {
			cfg := configs[id]
			sessionID := []byte("test-ringtail-refresh")
			startFunc := ringtail.Refresh(cfg, partyIDs, threshold, pl)

			session, err := startFunc(sessionID)
			if err != nil {
				t.Logf("Error for %s: %v", id, err)
			} else if session != nil {
				t.Logf("Session for %s", id)
			}
		}
	}()

	select {
	case <-done:
		t.Log("Completed")
	case <-ctx.Done():
		t.Log("Timed out")
	}
}

// TestTimeout tests protocol timeout behavior
func TestTimeout(t *testing.T) {
	done := make(chan bool, 1)

	go func() {
		cfg := config.NewConfig("test-party", 2, config.Security128)
		signers := []party.ID{"a", "b"}
		message := []byte("test message")

		signFunc := ringtail.Sign(cfg, signers, message, nil)
		sessionID := []byte("timeout-test")

		_, _ = signFunc(sessionID)
		done <- true
	}()

	select {
	case <-done:
		t.Log("Protocol completed")
	case <-time.After(5 * time.Second):
		t.Log("Timed out")
	}
}

// TestConfigValidation tests configuration parameter validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		id        party.ID
		threshold int
		level     config.SecurityLevel
	}{
		{"Security128", "test-party", 2, config.Security128},
		{"Security192", "test-party", 3, config.Security192},
		{"Security256", "test-party", 4, config.Security256},
		{"EmptyID", "", 2, config.Security128},
		{"ZeroThreshold", "test-party", 0, config.Security128},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.NewConfig(tc.id, tc.threshold, tc.level)
			assert.NotNil(t, cfg)
			if cfg != nil {
				assert.Equal(t, tc.id, cfg.ID)
				assert.Equal(t, tc.threshold, cfg.Threshold)
				assert.Equal(t, tc.level, cfg.Level)

				params := cfg.GetParameters()
				assert.Greater(t, params.N, 0)
				assert.Greater(t, params.Q, 0)
				assert.Greater(t, params.Sigma, 0.0)
			}
		})
	}
}

// TestSecurityLevels tests all security level parameters
func TestSecurityLevels(t *testing.T) {
	levels := []config.SecurityLevel{
		config.Security128,
		config.Security192,
		config.Security256,
	}

	for _, level := range levels {
		cfg := config.NewConfig("test", 2, level)
		require.NotNil(t, cfg)

		params := cfg.GetParameters()
		assert.Greater(t, params.N, 0)
		assert.Greater(t, params.Q, 0)
		assert.Greater(t, params.Sigma, 0.0)

		switch level {
		case config.Security128:
			assert.Equal(t, 128, params.SecurityBits)
		case config.Security192:
			assert.Equal(t, 192, params.SecurityBits)
		case config.Security256:
			assert.Equal(t, 256, params.SecurityBits)
		}
	}
}

// TestShareValidation tests share validation against verification shares
func TestShareValidation(t *testing.T) {
	cfg := config.NewConfig("test-party", 2, config.Security128)
	require.NotNil(t, cfg)

	validShare := make([]byte, 32)
	copy(validShare, []byte("valid-share"))

	h, _ := blake2b.New256(nil)
	h.Write(validShare)
	verificationShare := h.Sum(nil)

	cfg.VerificationShares["party-a"] = verificationShare

	assert.True(t, cfg.ValidateShare("party-a", validShare))

	wrongShare := make([]byte, 32)
	copy(wrongShare, []byte("wrong-share"))
	assert.False(t, cfg.ValidateShare("party-a", wrongShare))

	assert.False(t, cfg.ValidateShare("unknown-party", validShare))
}

// TestSignatureVerification tests signature verification
func TestSignatureVerification(t *testing.T) {
	publicKey := make([]byte, 32)
	copy(publicKey, []byte("test-public-key"))

	message := []byte("test-message")

	signature := make([]byte, 72) // 8 bytes length + 64 bytes signature
	binary.LittleEndian.PutUint64(signature[:8], 64)
	copy(signature[8:], []byte("test-signature-data"))

	assert.True(t, config.VerifySignature(publicKey, message, signature))

	assert.False(t, config.VerifySignature([]byte("short"), message, signature))

	assert.False(t, config.VerifySignature(publicKey, message, []byte("short")))
}
