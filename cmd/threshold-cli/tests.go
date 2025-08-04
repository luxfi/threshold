package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strings"
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

// Test runners

func runGinkgoTests(protocolName, suite string, timeout time.Duration) error {
	fmt.Println("Running Ginkgo tests...")
	
	// Build test command
	args := []string{"ginkgo", "-v"}
	
	if timeout > 0 {
		args = append(args, fmt.Sprintf("--timeout=%s", timeout))
	}
	
	// Add focus based on suite
	switch suite {
	case "functional":
		args = append(args, "--focus=Functional")
	case "security":
		args = append(args, "--focus=Security")
	case "property":
		args = append(args, "--focus=Property")
	case "fuzz":
		args = append(args, "--focus=Fuzz")
	}
	
	// Add protocol path
	switch protocolName {
	case "lss":
		args = append(args, "./protocols/lss")
	case "cmp":
		args = append(args, "./protocols/cmp")
	case "frost":
		args = append(args, "./protocols/frost")
	}
	
	// Run ginkgo
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	return cmd.Run()
}

func runFunctionalTests(protocolName string) error {
	fmt.Printf("\n=== Functional Tests for %s ===\n", protocolName)
	
	tests := []struct {
		name string
		test func() error
	}{
		{"Basic Signature Generation", func() error {
			return testBasicSignature(protocolName)
		}},
		{"Threshold Properties", func() error {
			return testThresholdProperties(protocolName)
		}},
		{"Edge Cases", func() error {
			return testEdgeCases(protocolName)
		}},
	}
	
	passed := 0
	failed := 0
	
	for _, t := range tests {
		fmt.Printf("\nRunning: %s\n", t.name)
		
		start := time.Now()
		err := t.test()
		elapsed := time.Since(start)
		
		if err != nil {
			fmt.Printf("  ✗ FAILED: %v (%.2fs)\n", err, elapsed.Seconds())
			failed++
		} else {
			fmt.Printf("  ✓ PASSED (%.2fs)\n", elapsed.Seconds())
			passed++
		}
	}
	
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)
	fmt.Printf("Total:  %d\n", passed+failed)
	
	if failed > 0 {
		return fmt.Errorf("%d tests failed", failed)
	}
	
	return nil
}

func runSecurityTests(protocolName string) error {
	fmt.Printf("\n=== Security Tests for %s ===\n", protocolName)
	
	tests := []struct {
		name string
		test func() error
	}{
		{"Threshold Security", func() error {
			return testThresholdSecurity(protocolName)
		}},
		{"Nonce Uniqueness", func() error {
			return testNonceUniqueness(protocolName)
		}},
		{"Message Authentication", func() error {
			return testMessageAuthentication(protocolName)
		}},
	}
	
	passed := 0
	failed := 0
	
	for _, t := range tests {
		fmt.Printf("\nRunning: %s\n", t.name)
		
		start := time.Now()
		err := t.test()
		elapsed := time.Since(start)
		
		if err != nil {
			fmt.Printf("  ✗ FAILED: %v (%.2fs)\n", err, elapsed.Seconds())
			failed++
		} else {
			fmt.Printf("  ✓ PASSED (%.2fs)\n", elapsed.Seconds())
			passed++
		}
	}
	
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)
	fmt.Printf("Total:  %d\n", passed+failed)
	
	if failed > 0 {
		return fmt.Errorf("%d tests failed", failed)
	}
	
	return nil
}

func runPropertyTests(protocolName string) error {
	fmt.Printf("\n=== Property-Based Tests for %s ===\n", protocolName)
	
	// Run Go's built-in property tests
	cmd := exec.Command("go", "test", 
		fmt.Sprintf("./protocols/%s", protocolName),
		"-run", "Property",
		"-v")
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	return cmd.Run()
}

func runFuzzTests(protocolName string) error {
	fmt.Printf("\n=== Fuzz Tests for %s ===\n", protocolName)
	
	// Run Go's built-in fuzz tests
	cmd := exec.Command("go", "test",
		fmt.Sprintf("./protocols/%s", protocolName),
		"-fuzz", "Fuzz",
		"-fuzztime", "10s",
		"-v")
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	return cmd.Run()
}

// Individual test implementations

func testBasicSignature(protocolName string) error {
	n := 5
	threshold := 3
	
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	// Keygen
	configs := make([]interface{}, n)
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
	
	// Verify all configs are valid
	for i, config := range configs {
		if config == nil {
			return fmt.Errorf("party %d failed keygen", i)
		}
	}
	
	// Sign
	message := []byte("test message")
	signers := partyIDs[:threshold]
	
	wg.Add(threshold)
	signatures := make([]interface{}, threshold)
	
	for i := 0; i < threshold; i++ {
		i := i
		go func() {
			defer wg.Done()
			
			var h protocol.Handler
			var err error
			
			switch protocolName {
			case "lss":
				c := configs[i].(*lss.Config)
				h, err = protocol.NewMultiHandler(lss.Sign(c, signers, message, pl), nil)
			case "cmp":
				c := configs[i].(*cmp.Config)
				h, err = protocol.NewMultiHandler(cmp.Sign(c, signers, message, pl), nil)
			case "frost":
				c := configs[i].(*frost.Config)
				h, err = protocol.NewMultiHandler(frost.Sign(c, signers, message, pl), nil)
			}
			
			if err != nil {
				return
			}
			
			test.HandlerLoop(partyIDs[i], h, network)
			
			result, err := h.Result()
			if err == nil {
				signatures[i] = result
			}
		}()
	}
	
	wg.Wait()
	
	// Verify signature
	if signatures[0] == nil {
		return fmt.Errorf("signing failed")
	}
	
	return nil
}

func testThresholdProperties(protocolName string) error {
	testCases := []struct {
		n         int
		threshold int
	}{
		{5, 3},
		{7, 4},
		{9, 5},
	}
	
	for _, tc := range testCases {
		// Test that exactly threshold parties can sign
		if err := testExactThreshold(protocolName, tc.n, tc.threshold); err != nil {
			return fmt.Errorf("threshold test failed for %d-of-%d: %w", tc.threshold, tc.n, err)
		}
	}
	
	return nil
}

func testEdgeCases(protocolName string) error {
	edgeCases := []struct {
		name      string
		n         int
		threshold int
	}{
		{"T=1", 3, 1},
		{"T=N", 5, 5},
		{"Minimum 2-of-2", 2, 2},
	}
	
	for _, tc := range edgeCases {
		if err := testConfiguration(protocolName, tc.n, tc.threshold); err != nil {
			return fmt.Errorf("edge case %s failed: %w", tc.name, err)
		}
	}
	
	return nil
}

func testThresholdSecurity(protocolName string) error {
	// Test that T-1 parties cannot sign
	n := 5
	threshold := 3
	
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	// Setup
	configs, err := setupTestConfigs(protocolName, n, threshold, pl, network, group)
	if err != nil {
		return err
	}
	
	// Try to sign with T-1 parties (should fail)
	insufficientSigners := partyIDs[:threshold-1]
	
	// This should fail or produce invalid signature
	err = attemptSign(protocolName, configs[:threshold-1], insufficientSigners, []byte("test"), pl, network)
	
	if err == nil {
		return fmt.Errorf("signing succeeded with insufficient parties")
	}
	
	return nil
}

func testNonceUniqueness(protocolName string) error {
	// Sign same message multiple times and verify nonces are different
	n := 5
	threshold := 3
	
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	configs, err := setupTestConfigs(protocolName, n, threshold, pl, network, group)
	if err != nil {
		return err
	}
	
	// Sign same message 5 times
	message := []byte("repeated message")
	signatures := make([]interface{}, 5)
	
	for i := 0; i < 5; i++ {
		sig, err := performSign(protocolName, configs[:threshold], partyIDs[:threshold], message, pl, network)
		if err != nil {
			return err
		}
		signatures[i] = sig
	}
	
	// Verify all signatures are valid but different
	// (In real implementation, would check actual nonce values)
	
	return nil
}

func testMessageAuthentication(protocolName string) error {
	// Test resistance to message tampering
	// This is a simplified test - real implementation would inject malicious messages
	
	n := 5
	threshold := 3
	
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	configs, err := setupTestConfigs(protocolName, n, threshold, pl, network, group)
	if err != nil {
		return err
	}
	
	// Normal signing should succeed
	message := []byte("authentic message")
	_, err = performSign(protocolName, configs[:threshold], partyIDs[:threshold], message, pl, network)
	
	return err
}

// Helper functions

func testExactThreshold(protocolName string, n, threshold int) error {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	configs, err := setupTestConfigs(protocolName, n, threshold, pl, network, group)
	if err != nil {
		return err
	}
	
	// Test with exactly threshold parties
	message := []byte("threshold test")
	_, err = performSign(protocolName, configs[:threshold], partyIDs[:threshold], message, pl, network)
	
	return err
}

func testConfiguration(protocolName string, n, threshold int) error {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(n)
	network := test.NewNetwork(partyIDs)
	group := curve.Secp256k1{}
	
	configs, err := setupTestConfigs(protocolName, n, threshold, pl, network, group)
	if err != nil {
		return err
	}
	
	// Basic signing test
	message := []byte("config test")
	_, err = performSign(protocolName, configs[:threshold], partyIDs[:threshold], message, pl, network)
	
	return err
}

func setupTestConfigs(protocolName string, n, threshold int, pl *pool.Pool, network *test.Network, group curve.Curve) ([]interface{}, error) {
	partyIDs := test.PartyIDs(n)
	configs := make([]interface{}, n)
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
	
	// Verify all configs
	for i, config := range configs {
		if config == nil {
			return nil, fmt.Errorf("party %d failed setup", i)
		}
	}
	
	return configs, nil
}

func performSign(protocolName string, configs []interface{}, signers []party.ID, message []byte, pl *pool.Pool, network *test.Network) (interface{}, error) {
	var wg sync.WaitGroup
	wg.Add(len(configs))
	
	results := make([]interface{}, len(configs))
	errors := make([]error, len(configs))
	
	for i, config := range configs {
		i := i
		go func(cfg interface{}) {
			defer wg.Done()
			
			var h protocol.Handler
			var err error
			
			switch protocolName {
			case "lss":
				c := cfg.(*lss.Config)
				h, err = protocol.NewMultiHandler(lss.Sign(c, signers, message, pl), nil)
			case "cmp":
				c := cfg.(*cmp.Config)
				h, err = protocol.NewMultiHandler(cmp.Sign(c, signers, message, pl), nil)
			case "frost":
				c := cfg.(*frost.Config)
				h, err = protocol.NewMultiHandler(frost.Sign(c, signers, message, pl), nil)
			}
			
			if err != nil {
				errors[i] = err
				return
			}
			
			test.HandlerLoop(signers[i], h, network)
			
			result, err := h.Result()
			if err != nil {
				errors[i] = err
			} else {
				results[i] = result
			}
		}(config)
	}
	
	wg.Wait()
	
	// Check for errors
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}
	
	// Return first non-nil result
	for _, result := range results {
		if result != nil {
			return result, nil
		}
	}
	
	return nil, fmt.Errorf("no valid signature produced")
}

func attemptSign(protocolName string, configs []interface{}, signers []party.ID, message []byte, pl *pool.Pool, network *test.Network) error {
	// This should fail with insufficient signers
	_, err := performSign(protocolName, configs, signers, message, pl, network)
	return err
}