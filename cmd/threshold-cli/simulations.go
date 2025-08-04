package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/lss"
	"runtime"
)

func simulateByzantine(protocolName string, rounds int, failureRate float64) error {
	fmt.Printf("\n=== Byzantine Simulation ===\n")
	fmt.Printf("Protocol: %s\n", protocolName)
	fmt.Printf("Rounds: %d\n", rounds)
	fmt.Printf("Byzantine failure rate: %.2f%%\n", failureRate*100)
	
	n := 7
	threshold := 4
	byzantineParties := int(math.Ceil(float64(n) * failureRate))
	
	fmt.Printf("Total parties: %d\n", n)
	fmt.Printf("Threshold: %d\n", threshold)
	fmt.Printf("Byzantine parties: %d\n", byzantineParties)
	
	if byzantineParties >= threshold {
		return fmt.Errorf("too many Byzantine parties (%d) for threshold (%d)", byzantineParties, threshold)
	}
	
	successCount := 0
	failureCount := 0
	
	for round := 0; round < rounds; round++ {
		if round%10 == 0 {
			fmt.Printf("\rProgress: %d/%d", round, rounds)
		}
		
		success, err := runByzantineRound(protocolName, n, threshold, byzantineParties)
		if err != nil {
			return fmt.Errorf("simulation error: %w", err)
		}
		
		if success {
			successCount++
		} else {
			failureCount++
		}
	}
	
	fmt.Printf("\n\n=== Results ===\n")
	fmt.Printf("Successful rounds: %d (%.2f%%)\n", successCount, float64(successCount)/float64(rounds)*100)
	fmt.Printf("Failed rounds: %d (%.2f%%)\n", failureCount, float64(failureCount)/float64(rounds)*100)
	fmt.Printf("Protocol resilience: %.2f%%\n", float64(successCount)/float64(rounds)*100)
	
	return nil
}

func simulateNetworkFailure(protocolName string, rounds int, failureRate float64) error {
	fmt.Printf("\n=== Network Failure Simulation ===\n")
	fmt.Printf("Protocol: %s\n", protocolName)
	fmt.Printf("Rounds: %d\n", rounds)
	fmt.Printf("Network failure rate: %.2f%%\n", failureRate*100)
	
	n := 9
	threshold := 5
	
	successCount := 0
	partialSuccessCount := 0
	failureCount := 0
	
	totalLatency := time.Duration(0)
	minLatency := time.Hour
	maxLatency := time.Duration(0)
	
	for round := 0; round < rounds; round++ {
		if round%10 == 0 {
			fmt.Printf("\rProgress: %d/%d", round, rounds)
		}
		
		start := time.Now()
		result, err := runNetworkFailureRound(protocolName, n, threshold, failureRate)
		elapsed := time.Since(start)
		
		if err != nil {
			return fmt.Errorf("simulation error: %w", err)
		}
		
		switch result {
		case "success":
			successCount++
			totalLatency += elapsed
			if elapsed < minLatency {
				minLatency = elapsed
			}
			if elapsed > maxLatency {
				maxLatency = elapsed
			}
		case "partial":
			partialSuccessCount++
		case "failure":
			failureCount++
		}
	}
	
	avgLatency := totalLatency / time.Duration(successCount)
	
	fmt.Printf("\n\n=== Results ===\n")
	fmt.Printf("Successful rounds: %d (%.2f%%)\n", successCount, float64(successCount)/float64(rounds)*100)
	fmt.Printf("Partial success: %d (%.2f%%)\n", partialSuccessCount, float64(partialSuccessCount)/float64(rounds)*100)
	fmt.Printf("Failed rounds: %d (%.2f%%)\n", failureCount, float64(failureCount)/float64(rounds)*100)
	fmt.Printf("\n=== Latency Statistics ===\n")
	fmt.Printf("Average: %v\n", avgLatency)
	fmt.Printf("Min: %v\n", minLatency)
	fmt.Printf("Max: %v\n", maxLatency)
	
	return nil
}

func simulateConcurrentSigning(protocolName string, rounds int) error {
	fmt.Printf("\n=== Concurrent Signing Simulation ===\n")
	fmt.Printf("Protocol: %s\n", protocolName)
	fmt.Printf("Rounds: %d\n", rounds)
	
	n := 7
	threshold := 4
	concurrentOps := []int{1, 2, 4, 8, 16}
	
	// Setup
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	configs, err := setupSimulationConfigs(protocolName, n, threshold, pl, network, group)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}
	
	fmt.Printf("\n=== Throughput Analysis ===\n")
	
	for _, ops := range concurrentOps {
		fmt.Printf("\nConcurrent operations: %d\n", ops)
		
		start := time.Now()
		successCount := int64(0)
		failureCount := int64(0)
		
		for round := 0; round < rounds; round++ {
			var wg sync.WaitGroup
			wg.Add(ops)
			
			for op := 0; op < ops; op++ {
				go func() {
					defer wg.Done()
					
					message := make([]byte, 32)
					rand.Read(message)
					
					err := runSingleSign(protocolName, configs[:threshold], message)
					if err == nil {
						atomic.AddInt64(&successCount, 1)
					} else {
						atomic.AddInt64(&failureCount, 1)
					}
				}()
			}
			
			wg.Wait()
		}
		
		elapsed := time.Since(start)
		totalOps := int64(rounds * ops)
		throughput := float64(successCount) / elapsed.Seconds()
		
		fmt.Printf("  Total operations: %d\n", totalOps)
		fmt.Printf("  Successful: %d (%.2f%%)\n", successCount, float64(successCount)/float64(totalOps)*100)
		fmt.Printf("  Failed: %d\n", failureCount)
		fmt.Printf("  Time: %v\n", elapsed)
		fmt.Printf("  Throughput: %.2f ops/sec\n", throughput)
	}
	
	return nil
}

func simulateLargeScale(protocolName string, rounds int) error {
	fmt.Printf("\n=== Large Scale Simulation ===\n")
	fmt.Printf("Protocol: %s\n", protocolName)
	fmt.Printf("Rounds: %d\n", rounds)
	
	testCases := []struct {
		n         int
		threshold int
	}{
		{11, 6},
		{15, 8},
		{21, 11},
		{31, 16},
		{51, 26},
	}
	
	for _, tc := range testCases {
		fmt.Printf("\n\nTesting %d-of-%d configuration...\n", tc.threshold, tc.n)
		
		// Memory usage before
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)
		
		// Run simulation
		totalTime := time.Duration(0)
		successCount := 0
		
		for round := 0; round < rounds; round++ {
			start := time.Now()
			
			err := runLargeScaleRound(protocolName, tc.n, tc.threshold)
			
			elapsed := time.Since(start)
			totalTime += elapsed
			
			if err == nil {
				successCount++
			}
			
			if round%5 == 0 {
				fmt.Printf("\r  Progress: %d/%d (%.2f%% success)", 
					round, rounds, float64(successCount)/float64(round+1)*100)
			}
		}
		
		// Memory usage after
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)
		
		avgTime := totalTime / time.Duration(rounds)
		memUsed := (m2.Alloc - m1.Alloc) / 1024 / 1024 // MB
		
		fmt.Printf("\n  === Results for %d-of-%d ===\n", tc.threshold, tc.n)
		fmt.Printf("  Success rate: %.2f%%\n", float64(successCount)/float64(rounds)*100)
		fmt.Printf("  Average time: %v\n", avgTime)
		fmt.Printf("  Memory used: ~%d MB\n", memUsed)
		fmt.Printf("  Time per party: %v\n", avgTime/time.Duration(tc.n))
	}
	
	return nil
}

// Helper functions

func runByzantineRound(protocolName string, n, threshold, byzantineCount int) (bool, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	// Mark some parties as Byzantine
	byzantineParties := make(map[party.ID]bool)
	for i := 0; i < byzantineCount; i++ {
		byzantineParties[partyIDs[i]] = true
	}
	
	// Create Byzantine network wrapper
	byzantineNetwork := &ByzantineNetwork{
		Network:          network,
		ByzantineParties: byzantineParties,
	}
	
	// Run protocol with Byzantine parties
	configs, err := setupSimulationConfigs(protocolName, n, threshold, pl, byzantineNetwork, group)
	if err != nil {
		return false, err
	}
	
	// Try to sign
	message := make([]byte, 32)
	rand.Read(message)
	
	err = runSingleSign(protocolName, configs[:threshold+byzantineCount], message)
	
	return err == nil, nil
}

func runNetworkFailureRound(protocolName string, n, threshold int, failureRate float64) (string, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	
	// Create unreliable network
	unreliableNetwork := &UnreliableNetwork{
		Network:     test.NewNetwork(partyIDs),
		FailureRate: failureRate,
	}
	
	group := curve.Secp256k1{}
	
	configs, err := setupSimulationConfigs(protocolName, n, threshold, pl, unreliableNetwork, group)
	if err != nil {
		return "failure", err
	}
	
	// Try to sign with all parties
	message := make([]byte, 32)
	rand.Read(message)
	
	successCount := 0
	var wg sync.WaitGroup
	wg.Add(n)
	
	for i, config := range configs {
		go func(idx int, cfg interface{}) {
			defer wg.Done()
			
			err := attemptSignWithConfig(protocolName, cfg, partyIDs, message, pl, unreliableNetwork)
			if err == nil {
				successCount++
			}
		}(i, config)
	}
	
	wg.Wait()
	
	if successCount >= threshold {
		return "success", nil
	} else if successCount > 0 {
		return "partial", nil
	}
	
	return "failure", nil
}

func runLargeScaleRound(protocolName string, n, threshold int) error {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	// Keygen
	configs, err := setupSimulationConfigs(protocolName, n, threshold, pl, network, group)
	if err != nil {
		return err
	}
	
	// Sign
	message := make([]byte, 32)
	rand.Read(message)
	
	return runSingleSign(protocolName, configs[:threshold], message)
}

func setupSimulationConfigs(protocolName string, n, threshold int, pl *pool.Pool, network protocol.Network, group curve.Curve) ([]interface{}, error) {
	partyIDs := test.PartyIDs(n)
	configs := make([]interface{}, n)
	errors := make([]error, n)
	
	var wg sync.WaitGroup
	wg.Add(n)
	
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
				h, err = protocol.NewMultiHandler(frost.Keygen(group, id, partyIDs, threshold, pl), nil)
			}
			
			if err != nil {
				errors[i] = err
				return
			}
			
			test.HandlerLoop(id, h, network)
			
			result, err := h.Result()
			if err != nil {
				errors[i] = err
			} else {
				configs[i] = result
			}
		}(id)
	}
	
	wg.Wait()
	
	// Check for errors
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}
	
	return configs, nil
}

func attemptSignWithConfig(protocolName string, config interface{}, partyIDs []party.ID, message []byte, pl *pool.Pool, network protocol.Network) error {
	var h protocol.Handler
	var err error
	var id party.ID
	
	switch protocolName {
	case "lss":
		c := config.(*lss.Config)
		id = c.ID
		h, err = protocol.NewMultiHandler(lss.Sign(c, partyIDs, message, pl), nil)
	case "cmp":
		c := config.(*cmp.Config)
		id = c.ID
		h, err = protocol.NewMultiHandler(cmp.Sign(c, partyIDs, message, pl), nil)
	case "frost":
		c := config.(*frost.Config)
		id = c.ID
		h, err = protocol.NewMultiHandler(frost.Sign(c, partyIDs, message, pl), nil)
	}
	
	if err != nil {
		return err
	}
	
	done := make(chan error, 1)
	go func() {
		test.HandlerLoop(id, h, network)
		_, err := h.Result()
		done <- err
	}()
	
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout")
	}
}

// Network simulation types

type ByzantineNetwork struct {
	*test.Network
	ByzantineParties map[party.ID]bool
}

func (b *ByzantineNetwork) Send(from, to party.ID, msg protocol.Message) {
	// Byzantine parties send corrupted messages
	if b.ByzantineParties[from] {
		// Randomly corrupt or drop message
		if rand.Float64() < 0.5 {
			return // Drop
		}
		// Otherwise send corrupted version (in real impl)
	}
	b.Network.Send(from, to, msg)
}

type UnreliableNetwork struct {
	*test.Network
	FailureRate float64
}

func (u *UnreliableNetwork) Send(from, to party.ID, msg protocol.Message) {
	// Randomly drop messages
	if rand.Float64() < u.FailureRate {
		return
	}
	
	// Add random delay
	delay := time.Duration(rand.Intn(100)) * time.Millisecond
	time.Sleep(delay)
	
	u.Network.Send(from, to, msg)
}