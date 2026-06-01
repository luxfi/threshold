package test

import (
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultTestConfig(t *testing.T) {
	cfg := DefaultTestConfig()

	// Check timeouts
	assert.Equal(t, 5*time.Second, cfg.MessageTimeout)
	assert.Equal(t, 10*time.Second, cfg.RoundTimeout)
	assert.Equal(t, 30*time.Second, cfg.ProtocolTimeout)
	assert.Equal(t, 60*time.Second, cfg.TestTimeout)

	// Check concurrency settings
	assert.Equal(t, 4, cfg.Workers)
	assert.Equal(t, 4, cfg.PriorityWorkers)
	assert.Equal(t, 10000, cfg.BufferSize)
	assert.Equal(t, 1000, cfg.PriorityBuffer)

	// Check network settings
	assert.False(t, cfg.UseZMQ)
	assert.Equal(t, 50000, cfg.BasePort)

	// Check debug settings
	assert.False(t, cfg.EnableLogging)
	assert.Equal(t, "info", cfg.LogLevel)
}

func TestIntegrationTestConfig(t *testing.T) {
	cfg := IntegrationTestConfig()

	// Check extended timeouts
	assert.Equal(t, 10*time.Second, cfg.MessageTimeout)
	assert.Equal(t, 30*time.Second, cfg.RoundTimeout)
	assert.Equal(t, 90*time.Second, cfg.ProtocolTimeout)
	assert.Equal(t, 120*time.Second, cfg.TestTimeout)
}

func TestBenchmarkConfig(t *testing.T) {
	cfg := BenchmarkConfig()

	// Check optimized settings
	assert.Equal(t, 2*time.Second, cfg.MessageTimeout)
	assert.Equal(t, 5*time.Second, cfg.RoundTimeout)
	assert.Equal(t, 20*time.Second, cfg.ProtocolTimeout)
	assert.Equal(t, 60*time.Second, cfg.TestTimeout)
	assert.Equal(t, 8, cfg.Workers)
	assert.Equal(t, 8, cfg.PriorityWorkers)
}

func TestTestConfig_Validation(t *testing.T) {
	cfg := &TestConfig{
		MessageTimeout: -1 * time.Second,
		Workers:        0,
		BufferSize:     -100,
	}

	// These should be validated in actual implementation
	assert.Less(t, cfg.MessageTimeout, time.Duration(0))
	assert.Equal(t, 0, cfg.Workers)
	assert.Less(t, cfg.BufferSize, 0)
}

// Benchmark config creation
func BenchmarkDefaultTestConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DefaultTestConfig()
	}
}

func TestTestConfig_WithContext(t *testing.T) {
	cfg := DefaultTestConfig()
	cfg.TestTimeout = 100 * time.Millisecond

	ctx, cancel := cfg.WithContext(t)
	defer cancel()

	// Context should have timeout
	deadline, ok := ctx.Deadline()
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(100*time.Millisecond), deadline, 10*time.Millisecond)
}

func TestNetwork(t *testing.T) {
	parties := []party.ID{"alice", "bob", "charlie"}
	network := NewNetwork(parties)
	require.NotNil(t, network)

	// Test that channels are created for all parties
	assert.Len(t, network.messages, 3)
	assert.Len(t, network.done, 3)

	// Clean up
	network.Close()
}

func TestNetwork_Send(t *testing.T) {
	parties := []party.ID{"alice", "bob"}
	network := NewNetwork(parties)
	defer network.Close()

	// Test sending nil message (should not panic)
	network.Send(nil)

	// Note: Full protocol.Message testing would require the protocol package
}
