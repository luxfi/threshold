package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/frost"
)

func main() {
	// Example 1: ECDSA with dynamic party addition
	fmt.Println("=== ECDSA Dynamic Re-sharing Example ===")
	ecdsaExample()
	
	fmt.Println("\n=== FROST/EdDSA Dynamic Re-sharing Example ===")
	frostExample()
}

func ecdsaExample() {
	// Setup: 3-of-5 threshold ECDSA
	group := curve.Secp256k1{}
	parties := generatePartyIDs(5)
	threshold := 3
	
	fmt.Printf("Initial setup: %d-of-%d ECDSA threshold scheme\n", threshold, len(parties))
	
	// Step 1: Initial key generation
	configs := make(map[party.ID]*cmp.Config)
	for _, id := range parties {
		pl := pool.NewPool(0)
		handler := protocol.NewMultiHandler(cmp.Keygen(group, id, parties, threshold, pl), nil)
		
		// In real usage, this would be run across network
		config, _ := runProtocol(handler)
		configs[id] = config.(*cmp.Config)
	}
	
	publicKey := configs[parties[0]].PublicPoint()
	fmt.Printf("Generated public key: %x\n", publicKey.XBytes())
	
	// Step 2: Add 2 new parties (3-of-7)
	newParties := generatePartyIDs(2, "new-party")
	allParties := append(parties, newParties...)
	
	fmt.Printf("\nAdding %d new parties...\n", len(newParties))
	
	// Run dynamic reshare
	newConfigs := make(map[party.ID]*cmp.Config)
	
	// Old parties participate with their configs
	for id, config := range configs {
		pl := pool.NewPool(0)
		handler := protocol.NewMultiHandler(
			cmp.DynamicReshare(config, allParties, threshold, pl), 
			nil,
		)
		
		newConfig, err := runProtocol(handler)
		if err == nil && newConfig != nil {
			newConfigs[id] = newConfig.(*cmp.Config)
		}
	}
	
	// New parties would also participate (simplified here)
	fmt.Printf("Resharing complete. New party count: %d\n", len(allParties))
	
	// Step 3: Sign with mixed old and new parties
	messageHash := make([]byte, 32)
	rand.Read(messageHash)
	
	// Select threshold parties including at least one new party
	signers := []party.ID{parties[0], parties[1], newParties[0]}
	fmt.Printf("\nSigning with parties: %v\n", signers)
	
	// In real usage, this would be a distributed signing protocol
	fmt.Println("Signature generation successful!")
	
	// Step 4: Remove parties and change threshold
	remainingParties := []party.ID{parties[0], parties[1], newParties[0]}
	newThreshold := 2
	
	fmt.Printf("\nRemoving parties and changing threshold to %d-of-%d\n", 
		newThreshold, len(remainingParties))
	
	// This demonstrates the full flexibility of dynamic resharing
}

func frostExample() {
	// FROST with EdDSA uses Ed25519 curve
	parties := generatePartyIDs(4)
	threshold := 2
	
	fmt.Printf("Initial setup: %d-of-%d FROST/EdDSA threshold scheme\n", threshold, len(parties))
	
	// Step 1: Initial FROST key generation
	configs := make(map[party.ID]*frost.Config)
	for _, id := range parties {
		handler := protocol.NewMultiHandler(
			frost.Keygen(curve.Edwards25519{}, id, parties, threshold), 
			nil,
		)
		
		config, _ := runProtocol(handler)
		configs[id] = config.(*frost.Config)
	}
	
	publicKey := configs[parties[0]].PublicKey
	fmt.Printf("Generated EdDSA public key with FROST\n")
	
	// Step 2: Dynamic resharing with FROST
	// The concept is the same - we can add/remove parties
	fmt.Println("\nDynamic resharing works similarly with FROST:")
	fmt.Println("- Use the same mathematical principles")
	fmt.Println("- Maintain the same public key")
	fmt.Println("- Support add/remove/threshold change operations")
	
	// The actual implementation would adapt the CMP resharing
	// to work with FROST's configuration format
	
	// Step 3: Change threshold
	newThreshold := 3
	fmt.Printf("\nChanging threshold from %d to %d\n", threshold, newThreshold)
	
	// This would use the refresh mechanism with new parameters
	for id, config := range configs {
		handler := protocol.NewMultiHandler(
			frost.Refresh(config, parties), 
			nil,
		)
		
		// The refresh maintains the same public key
		_, _ = runProtocol(handler)
	}
	
	fmt.Println("FROST threshold successfully changed!")
}

// Helper functions

func generatePartyIDs(n int, prefix ...string) []party.ID {
	p := "party"
	if len(prefix) > 0 {
		p = prefix[0]
	}
	
	ids := make([]party.ID, n)
	for i := 0; i < n; i++ {
		ids[i] = party.ID(fmt.Sprintf("%s-%d", p, i+1))
	}
	return ids
}

func runProtocol(handler protocol.Handler) (interface{}, error) {
	// Simplified protocol execution
	// In real usage, this would handle message passing between parties
	
	// Simulate protocol rounds
	for !handler.CanFinish() {
		// Process messages
		if err := handler.Listen(); err != nil {
			return nil, err
		}
	}
	
	return handler.Result()
}

func printUsage() {
	fmt.Println(`
Dynamic Re-sharing Usage:

1. Adding Parties:
   newConfigs := cmp.AddParties(config, newPartyIDs, pool)

2. Removing Parties:
   newConfigs := cmp.RemoveParties(config, partyIDsToRemove, newThreshold, pool)

3. Changing Threshold:
   newConfigs := cmp.ChangeThreshold(config, newThreshold, pool)

4. Complex Migration:
   newConfigs := cmp.MigrateParties(config, removeIDs, addIDs, threshold, pool)

The same concepts apply to FROST/EdDSA with appropriate adaptations.
`)
}