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

const (
	protocolLSS   = "lss"
	protocolCMP   = "cmp"
	protocolFROST = "frost"
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
			if _, err := rand.Read(message); err != nil {
				panic(fmt.Sprintf("failed to generate random message: %v", err))
			}

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
		name          string
		newThreshold  int
		addParties    int
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
				cfg, ok := c.(*lss.Config)
				if !ok {
					panic("invalid config type for lss protocol")
				}
				iterConfigs[j] = cfg
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

			var h *protocol.Handler
			var err error

			switch protocolName {
			case protocolLSS:
				h, err = protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
			case protocolCMP:
				h, err = protocol.NewMultiHandler(cmp.Keygen(group, id, partyIDs, threshold, pl), nil)
			case protocolFROST:
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

			var h *protocol.Handler
			var err error

			switch protocolName {
			case protocolLSS:
				h, err = protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
			case protocolCMP:
				h, err = protocol.NewMultiHandler(cmp.Keygen(group, id, partyIDs, threshold, pl), nil)
			case protocolFROST:
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

func extractPartyIDs(protocolName string, configs []interface{}) []party.ID {
	partyIDs := make([]party.ID, len(configs))
	
	for i, c := range configs {
		switch protocolName {
		case protocolLSS:
			cfg, ok := c.(*lss.Config)
			if !ok {
				panic("invalid config type for lss protocol")
			}
			partyIDs[i] = cfg.ID
		case protocolCMP:
			cfg, ok := c.(*cmp.Config)
			if !ok {
				panic("invalid config type for cmp protocol")
			}
			partyIDs[i] = cfg.ID
		case protocolFROST:
			cfg, ok := c.(*frost.Config)
			if !ok {
				panic("invalid config type for frost protocol")
			}
			partyIDs[i] = cfg.ID
		}
	}
	
	return partyIDs
}

func createSignHandler(protocolName string, cfg interface{}, partyIDs []party.ID, message []byte, pl *pool.Pool) (*protocol.Handler, error) {
	switch protocolName {
	case protocolLSS:
		c, ok := cfg.(*lss.Config)
		if !ok {
			panic("invalid config type for lss protocol")
		}
		return protocol.NewMultiHandler(lss.Sign(c, partyIDs, message, pl), nil)
	case protocolCMP:
		c, ok := cfg.(*cmp.Config)
		if !ok {
			panic("invalid config type for cmp protocol")
		}
		return protocol.NewMultiHandler(cmp.Sign(c, partyIDs, message, pl), nil)
	case protocolFROST:
		c, ok := cfg.(*frost.Config)
		if !ok {
			panic("invalid config type for frost protocol")
		}
		return protocol.NewMultiHandler(frost.Sign(c, partyIDs, message), nil)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", protocolName)
	}
}

func runSingleSign(protocolName string, configs []interface{}, message []byte) error {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	partyIDs := extractPartyIDs(protocolName, configs)
	network := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(len(configs))

	for i, config := range configs {
		go func(idx int, cfg interface{}) {
			defer wg.Done()

			h, err := createSignHandler(protocolName, cfg, partyIDs, message, pl)
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

			h, err := protocol.NewMultiHandler(lss.Reshare(c, newPartyIDs, newThreshold, pl), nil)
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

			emptyConfig := lss.EmptyConfig(configs[0].Group)
			emptyConfig.ID = id
			emptyConfig.Generation = configs[0].Generation

			h, err := protocol.NewMultiHandler(lss.Reshare(emptyConfig, newPartyIDs, newThreshold, pl), nil)
			if err != nil {
				return
			}

			test.HandlerLoop(id, h, network)
		}(newID)
	}

	wg.Wait()
	return nil
}
