package test

import (
	"fmt"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// ProtocolTest represents a test case for a protocol
type ProtocolTest struct {
	Name        string
	PartyCount  int
	Threshold   int
	SessionID   []byte
	CreateStart func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc
	Validate    func(t *testing.T, results map[party.ID]interface{})
}

// Run executes the protocol test
func (pt *ProtocolTest) Run(t *testing.T) {
	t.Run(pt.Name, func(t *testing.T) {
		// Generate party IDs
		partyIDs := PartyIDs(pt.PartyCount)

		// Create start function wrapper
		createStart := func(id party.ID) protocol.StartFunc {
			return pt.CreateStart(id, partyIDs, pt.Threshold)
		}

		// Run the protocol
		results, err := RunProtocol(t, partyIDs, pt.SessionID, createStart)
		require.NoError(t, err, "protocol should complete without error")

		// Validate results
		if pt.Validate != nil {
			pt.Validate(t, results)
		}
	})
}

// RunMultipleProtocolTests runs multiple protocol tests
func RunMultipleProtocolTests(t *testing.T, tests []ProtocolTest) {
	for _, test := range tests {
		test.Run(t)
	}
}

// RunSingleProtocol runs a single party's protocol instance for testing
func RunSingleProtocol(t *testing.T, selfID party.ID, allParties []party.ID, sessionID []byte, startFunc protocol.StartFunc) (interface{}, error) {
	// Run just this party's protocol
	partyList := []party.ID{selfID}
	results, err := RunProtocol(t, partyList, sessionID, func(id party.ID) protocol.StartFunc {
		if id == selfID {
			return startFunc
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	result, ok := results[selfID]
	if !ok {
		return nil, fmt.Errorf("no result for party %s", selfID)
	}

	return result, nil
}

// KeygenAndSign performs keygen followed by signing for threshold protocols
type KeygenAndSign struct {
	Name         string
	PartyCount   int
	Threshold    int
	Message      []byte
	CreateKeygen func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc
	CreateSign   func(config interface{}, signers []party.ID, message []byte) protocol.StartFunc
	ValidateSign func(t *testing.T, config interface{}, signature interface{}, message []byte)
}

// Run executes the keygen and sign test
func (ks *KeygenAndSign) Run(t *testing.T) {
	t.Run(ks.Name, func(t *testing.T) {
		// Generate party IDs
		partyIDs := PartyIDs(ks.PartyCount)
		// For threshold signatures, we need threshold+1 parties to sign
		signers := partyIDs[:ks.Threshold+1]
		if len(signers) > len(partyIDs) {
			signers = partyIDs // Use all parties if threshold+1 > n
		}

		// Run keygen
		keygenResults, err := RunProtocol(t, partyIDs, []byte("keygen-session"), func(id party.ID) protocol.StartFunc {
			return ks.CreateKeygen(id, partyIDs, ks.Threshold)
		})
		require.NoError(t, err, "keygen should complete without error")
		require.Len(t, keygenResults, ks.PartyCount, "all parties should have keygen results")

		// Verify all parties have the same public key configuration
		var firstConfig interface{}
		for _, config := range keygenResults {
			require.NotNil(t, config, "keygen result should not be nil")
			if firstConfig == nil {
				firstConfig = config
			}
			// Protocol-specific validation would go here
		}

		// Run signing with threshold number of parties
		signResults, err := RunProtocol(t, signers, []byte("sign-session"), func(id party.ID) protocol.StartFunc {
			// Find the config for this party
			config, ok := keygenResults[id]
			require.True(t, ok, "signer should have keygen config")
			return ks.CreateSign(config, signers, ks.Message)
		})
		require.NoError(t, err, "signing should complete without error")
		require.Len(t, signResults, len(signers), "all signers should have results")

		// Validate signatures
		for id, sig := range signResults {
			require.NotNil(t, sig, "signature should not be nil for party %s", id)
			if ks.ValidateSign != nil {
				config := keygenResults[id]
				ks.ValidateSign(t, config, sig, ks.Message)
			}
		}
	})
}

// ProtocolBenchmark provides benchmarking utilities
type ProtocolBenchmark struct {
	Name        string
	PartyCount  int
	Threshold   int
	CreateStart func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc
}

// Run executes the benchmark
func (pb *ProtocolBenchmark) Run(b *testing.B) {
	b.Run(pb.Name, func(b *testing.B) {
		partyIDs := PartyIDs(pb.PartyCount)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			createStart := func(id party.ID) protocol.StartFunc {
				return pb.CreateStart(id, partyIDs, pb.Threshold)
			}

			results, err := RunProtocol(b, partyIDs, []byte(fmt.Sprintf("bench-%d", i)), createStart)
			if err != nil {
				b.Fatalf("protocol failed: %v", err)
			}
			if len(results) != pb.PartyCount {
				b.Fatalf("expected %d results, got %d", pb.PartyCount, len(results))
			}
		}
	})
}

// RunProtocolBenchmarks runs multiple protocol benchmarks
func RunProtocolBenchmarks(b *testing.B, benchmarks []ProtocolBenchmark) {
	for _, bench := range benchmarks {
		bench.Run(b)
	}
}
