package cmp

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/common"
	"github.com/stretchr/testify/require"
)

func TestKeygenWithContext_Cancellation(t *testing.T) {
	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	
	// Setup runtime
	rt := common.Runtime{
		SessionID: []byte("test-session"),
		SelfID:    "alice",
		PartyIDs:  []party.ID{"alice", "bob", "charlie"},
		Threshold: 2,
		Group:     curve.Secp256k1{},
	}
	
	// Setup config with short timeout
	cfg := common.Config{
		MaxRounds:      10,
		RoundTimeout:   100 * time.Millisecond,
		MessageTimeout: 50 * time.Millisecond,
	}
	
	// Setup dependencies
	deps := common.Deps{
		Pool: pool.NewPool(0),
	}
	
	// Start keygen in background
	done := make(chan error, 1)
	go func() {
		_, err := KeygenWithContext(ctx, rt, cfg, deps)
		done <- err
	}()
	
	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()
	
	// Verify cancellation was respected
	err := <-done
	require.ErrorIs(t, err, context.Canceled)
}

func TestKeygenWithContext_Timeout(t *testing.T) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	
	// Setup runtime
	rt := common.Runtime{
		SessionID: []byte("test-session"),
		SelfID:    "alice",
		PartyIDs:  []party.ID{"alice", "bob", "charlie"},
		Threshold: 2,
		Group:     curve.Secp256k1{},
	}
	
	// Setup config with long round timeout (will exceed context timeout)
	cfg := common.Config{
		MaxRounds:      10,
		RoundTimeout:   1 * time.Second, // Longer than context timeout
		MessageTimeout: 50 * time.Millisecond,
	}
	
	// Setup dependencies
	deps := common.Deps{
		Pool: pool.NewPool(0),
	}
	
	// Run keygen
	_, err := KeygenWithContext(ctx, rt, cfg, deps)
	
	// Should timeout
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestSignWithContext_MultipleGoroutines(t *testing.T) {
	// Test that signing properly manages multiple goroutines with context
	ctx := context.Background()
	
	// First generate keys
	rt := common.Runtime{
		SessionID: []byte("test-session"),
		SelfID:    "alice",
		PartyIDs:  []party.ID{"alice", "bob", "charlie"},
		Threshold: 2,
		Group:     curve.Secp256k1{},
	}
	
	cfg := common.DefaultConfig()
	deps := common.Deps{
		Pool: pool.NewPool(0),
	}
	
	configs, err := KeygenWithContext(ctx, rt, cfg, deps)
	require.NoError(t, err)
	require.Len(t, configs, 3)
	
	// Create signing context with timeout
	signCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	// Sign a message
	messageHash := []byte("test message hash")
	signers := []party.ID{"alice", "bob"}
	
	sig, err := SignWithContext(signCtx, rt, configs[0], signers, messageHash, deps)
	require.NoError(t, err)
	require.NotNil(t, sig)
}

func TestRefreshWithContext_Rollback(t *testing.T) {
	// Test refresh with context cancellation triggers proper rollback
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Setup
	rt := common.Runtime{
		SessionID: []byte("test-session"),
		SelfID:    "alice",
		PartyIDs:  []party.ID{"alice", "bob", "charlie"},
		Threshold: 2,
		Group:     curve.Secp256k1{},
	}
	
	cfg := common.Config{
		EnableStateRollback: true,
		MaxRounds:           5,
		RoundTimeout:        100 * time.Millisecond,
	}
	
	deps := common.Deps{
		Pool: pool.NewPool(0),
		Storage: &mockStorage{
			data: make(map[string][]byte),
		},
	}
	
	// Generate initial config
	configs, err := KeygenWithContext(ctx, rt, cfg, deps)
	require.NoError(t, err)
	
	// Start refresh in background
	refreshDone := make(chan error, 1)
	go func() {
		_, err := RefreshWithContext(ctx, rt, configs[0], deps)
		refreshDone <- err
	}()
	
	// Cancel midway
	time.Sleep(150 * time.Millisecond)
	cancel()
	
	// Verify cancellation
	err = <-refreshDone
	require.ErrorIs(t, err, context.Canceled)
	
	// Verify state was rolled back (check storage)
	if deps.Storage != nil {
		// State should be cleaned up after cancellation
		keys, err := deps.Storage.List("refresh-")
		require.NoError(t, err)
		require.Empty(t, keys, "refresh state should be cleaned up after cancellation")
	}
}

// mockStorage implements common.Storage for testing
type mockStorage struct {
	data map[string][]byte
}

func (m *mockStorage) Save(key string, value []byte) error {
	m.data[key] = value
	return nil
}

func (m *mockStorage) Load(key string) ([]byte, error) {
	value, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return value, nil
}

func (m *mockStorage) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockStorage) List(prefix string) ([]string, error) {
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// Benchmark with context
func BenchmarkKeygenWithContext(b *testing.B) {
	ctx := context.Background()
	rt := common.Runtime{
		SessionID: []byte("bench-session"),
		SelfID:    "alice",
		PartyIDs:  []party.ID{"alice", "bob", "charlie", "dave", "eve"},
		Threshold: 3,
		Group:     curve.Secp256k1{},
	}
	cfg := common.DefaultConfig()
	deps := common.Deps{
		Pool: pool.NewPool(0),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := KeygenWithContext(ctx, rt, cfg, deps)
		require.NoError(b, err)
	}
}

// Example showing proper context usage
func ExampleKeygenWithContext() {
	// Create root context with overall timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Setup runtime
	rt := common.Runtime{
		SessionID: []byte("example-session"),
		SelfID:    "alice",
		PartyIDs:  []party.ID{"alice", "bob", "charlie"},
		Threshold: 2,
		Group:     curve.Secp256k1{},
	}
	
	// Configure protocol
	cfg := common.Config{
		MaxRounds:                 10,
		RoundTimeout:              2 * time.Second,
		EnableAbortIdentification: true,
		EnableStateRollback:       true,
	}
	
	// Setup dependencies
	deps := common.Deps{
		Pool: pool.NewPool(0),
		Logger: &consoleLogger{}, // Your logger implementation
		Metrics: &prometheusCollector{}, // Your metrics implementation
	}
	
	// Run keygen with proper context
	configs, err := KeygenWithContext(ctx, rt, cfg, deps)
	if err != nil {
		if err == context.DeadlineExceeded {
			fmt.Println("Keygen timed out")
		} else if err == context.Canceled {
			fmt.Println("Keygen was cancelled")
		} else {
			fmt.Printf("Keygen failed: %v\n", err)
		}
		return
	}
	
	fmt.Printf("Generated %d configs\n", len(configs))
	// Output: Generated 3 configs
}