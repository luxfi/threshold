package main

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/lss"
)

func benchmarkKeygen(protocolName string, iterations int) error {
	fmt.Printf("\n=== Keygen Benchmark ===\n")
	
	testCases := []struct {
		name      string
		n         int
		threshold int
	}{
		{"3-of-5", 5, 3},
		{"5-of-9", 9, 5},
		{"7-of-11", 11, 7},
	}

	for _, tc := range testCases {
		fmt.Printf("\nTesting %s:\n", tc.name)
		
		var totalTime time.Duration
		var minTime = time.Hour
		var maxTime time.Duration
		
		for i := 0; i < iterations; i++ {
			start := time.Now()
			
			if err := runSingleKeygen(protocolName, tc.n, tc.threshold); err != nil {
				return fmt.Errorf("keygen failed: %w", err)
			}
			
			elapsed := time.Since(start)
			totalTime += elapsed
			
			if elapsed < minTime {
				minTime = elapsed
			}
			if elapsed > maxTime {
				maxTime = elapsed
			}
		}
		
		avgTime := totalTime / time.Duration(iterations)
		
		fmt.Printf("  Average: %v\n", avgTime)
		fmt.Printf("  Min:     %v\n", minTime)
		fmt.Printf("  Max:     %v\n", maxTime)
		fmt.Printf("  Total:   %v\n", totalTime)
	}
	
	return nil
}

func benchmarkSign(protocolName string, iterations int) error {
	fmt.Printf("\n=== Sign Benchmark ===\n")
	
	// Setup phase
	n := 5
	threshold := 3
	
	fmt.Printf("Setting up %d-of-%d configuration...\n", threshold, n)
	
	// First generate keys
	configs, err := setupBenchmarkConfigs(protocolName, n, threshold)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}
	
	// Run signing benchmarks
	testCases := []struct {
		name    string
		signers int
	}{
		{"threshold signers", threshold},
		{"all signers", n},
	}
	
	for _, tc := range testCases {
		fmt.Printf("\nTesting with %s:\n", tc.name)
		
		var totalTime time.Duration
		var minTime = time.Hour
		var maxTime time.Duration
		
		for i := 0; i < iterations; i++ {
			message := make([]byte, 32)
			rand.Read(message)
			
			start := time.Now()
			
			if err := runSingleSign(protocolName, configs[:tc.signers], message); err != nil {
				return fmt.Errorf("signing failed: %w", err)
			}
			
			elapsed := time.Since(start)
			totalTime += elapsed
			
			if elapsed < minTime {
				minTime = elapsed
			}
			if elapsed > maxTime {
				maxTime = elapsed
			}
		}
		
		avgTime := totalTime / time.Duration(iterations)
		
		fmt.Printf("  Average: %v\n", avgTime)
		fmt.Printf("  Min:     %v\n", minTime)
		fmt.Printf("  Max:     %v\n", maxTime)
		fmt.Printf("  Total:   %v\n", totalTime)
	}
	
	return nil
}

func benchmarkReshare(iterations int) error {
	fmt.Printf("\n=== Reshare Benchmark (LSS only) ===\n")
	
	// Setup initial configuration
	initialN := 5
	initialThreshold := 3
	
	fmt.Printf("Setting up initial %d-of-%d configuration...\n", initialThreshold, initialN)
	
	configs, err := setupBenchmarkConfigs("lss", initialN, initialThreshold)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}
	
	testCases := []struct {
		name         string
		newThreshold int
		addParties   int
		removeParties int
	}{
		{"increase threshold 3->4", 4, 0, 0},
		{"add 2 parties", 3, 2, 0},
		{"remove 1 party", 3, 0, 1},
		{"add 1 remove 1", 3, 1, 1},
	}
	
	for _, tc := range testCases {
		fmt.Printf("\nTesting %s:\n", tc.name)
		
		var totalTime time.Duration
		var minTime = time.Hour
		var maxTime time.Duration
		
		for i := 0; i < iterations; i++ {
			// Clone configs for this iteration
			iterConfigs := make([]*lss.Config, len(configs))
			for j, c := range configs {
				iterConfigs[j] = c.(*lss.Config)
			}
			
			start := time.Now()
			
			if err := runSingleReshare(iterConfigs, tc.newThreshold, tc.addParties, tc.removeParties); err != nil {
				return fmt.Errorf("reshare failed: %w", err)
			}
			
			elapsed := time.Since(start)
			totalTime += elapsed
			
			if elapsed < minTime {
				minTime = elapsed
			}
			if elapsed > maxTime {
				maxTime = elapsed
			}
		}
		
		avgTime := totalTime / time.Duration(iterations)
		
		fmt.Printf("  Average: %v\n", avgTime)
		fmt.Printf("  Min:     %v\n", minTime)
		fmt.Printf("  Max:     %v\n", maxTime)
		fmt.Printf("  Total:   %v\n", totalTime)
	}
	
	return nil
}

// Helper functions

func runSingleKeygen(protocolName string, n, threshold int) error {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	
	var wg sync.WaitGroup
	wg.Add(n)
	
	group := curve.Secp256k1{}
	
	for _, id := range partyIDs {
		go func(id party.ID) {
			defer wg.Done()
			
			var h protocol.Handler
			var err error
			
			switch protocolName {
			case "lss":
				h, err = protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
			case "cmp":
				h, err = protocol.NewMultiHandler(cmp.Keygen(group, id, partyIDs, threshold, pl), nil)
			case "frost":
				h, err = protocol.NewMultiHandler(frost.Keygen(group, id, partyIDs, threshold), nil)
			}
			
			if err != nil {
				return
			}
			
			test.HandlerLoop(id, h, network)
		}(id)
	}
	
	wg.Wait()
	return nil
}

func setupBenchmarkConfigs(protocolName string, n, threshold int) ([]interface{}, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	
	configs := make([]interface{}, n)
	var wg sync.WaitGroup
	wg.Add(n)
	
	group := curve.Secp256k1{}
	
	for i, id := range partyIDs {
		i := i
		go func(id party.ID) {
			defer wg.Done()
			
			var h protocol.Handler
			var err error
			
			switch protocolName {
			case "lss":
				h, err = protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
			case "cmp":
				h, err = protocol.NewMultiHandler(cmp.Keygen(group, id, partyIDs, threshold, pl), nil)
			case "frost":
				h, err = protocol.NewMultiHandler(frost.Keygen(group, id, partyIDs, threshold), nil)
			}
			
			if err != nil {
				return
			}
			
			test.HandlerLoop(id, h, network)
			
			result, err := h.Result()
			if err == nil {
				configs[i] = result
			}
		}(id)
	}
	
	wg.Wait()
	return configs, nil
}

func runSingleSign(protocolName string, configs []interface{}, message []byte) error {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	var partyIDs []party.ID
	
	// Extract party IDs based on protocol
	switch protocolName {
	case "lss":
		partyIDs = make([]party.ID, len(configs))
		for i, c := range configs {
			partyIDs[i] = c.(*lss.Config).ID
		}
	case "cmp":
		partyIDs = make([]party.ID, len(configs))
		for i, c := range configs {
			partyIDs[i] = c.(*cmp.Config).ID
		}
	case "frost":
		partyIDs = make([]party.ID, len(configs))
		for i, c := range configs {
			partyIDs[i] = c.(*frost.Config).ID
		}
	}
	
	network := test.NewNetwork(partyIDs)
	
	var wg sync.WaitGroup
	wg.Add(len(configs))
	
	for i, config := range configs {
		go func(idx int, cfg interface{}) {
			defer wg.Done()
			
			var h protocol.Handler
			var err error
			
			switch protocolName {
			case "lss":
				c := cfg.(*lss.Config)
				h, err = protocol.NewMultiHandler(lss.Sign(c, partyIDs, message, pl), nil)
			case "cmp":
				c := cfg.(*cmp.Config)
				h, err = protocol.NewMultiHandler(cmp.Sign(c, partyIDs, message, pl), nil)
			case "frost":
				c := cfg.(*frost.Config)
				h, err = protocol.NewMultiHandler(frost.Sign(c, partyIDs, message), nil)
			}
			
			if err != nil {
				return
			}
			
			test.HandlerLoop(partyIDs[idx], h, network)
		}(i, config)
	}
	
	wg.Wait()
	return nil
}

func runSingleReshare(configs []*lss.Config, newThreshold, addParties, removeParties int) error {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	// Determine final configuration
	remainingConfigs := configs
	if removeParties > 0 {
		remainingConfigs = configs[:len(configs)-removeParties]
	}
	
	// Create new party IDs
	newPartyIDs := make([]party.ID, addParties)
	for i := 0; i < addParties; i++ {
		newPartyIDs[i] = party.ID(fmt.Sprintf("new-%d", i))
	}
	
	// All parties involved in resharing
	allParties := make([]party.ID, len(remainingConfigs)+len(newPartyIDs))
	for i, c := range remainingConfigs {
		allParties[i] = c.ID
	}
	copy(allParties[len(remainingConfigs):], newPartyIDs)
	
	network := test.NewNetwork(allParties)
	
	var wg sync.WaitGroup
	wg.Add(len(allParties))
	
	// Existing parties reshare
	for _, config := range remainingConfigs {
		go func(c *lss.Config) {
			defer wg.Done()
			
			h, err := protocol.NewMultiHandler(lss.Reshare(c, newThreshold, newPartyIDs, pl), nil)
			if err != nil {
				return
			}
			
			test.HandlerLoop(c.ID, h, network)
		}(config)
	}
	
	// New parties join
	for _, newID := range newPartyIDs {
		go func(id party.ID) {
			defer wg.Done()
			
			emptyConfig := &lss.Config{
				ID:           id,
				Group:        configs[0].Group,
				PublicKey:    configs[0].PublicKey,
				Generation:   configs[0].Generation,
				PartyIDs:     remainingConfigs[0].PartyIDs,
				PublicShares: make(map[party.ID]curve.Point),
			}
			
			h, err := protocol.NewMultiHandler(lss.Reshare(emptyConfig, newThreshold, newPartyIDs, pl), nil)
			if err != nil {
				return
			}
			
			test.HandlerLoop(id, h, network)
		}(newID)
	}
	
	wg.Wait()
	return nil
}