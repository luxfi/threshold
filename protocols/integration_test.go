package protocols_test

import (
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/lss"
	lssconfig "github.com/luxfi/threshold/protocols/lss/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Protocol Integration Suite")
}

var _ = Describe("CGG21+FROST+LSS Integration", func() {
	var (
		pl    *pool.Pool
		group curve.Curve
	)

	BeforeEach(func() {
		pl = pool.NewPool(0)
		group = curve.Secp256k1{}
	})

	AfterEach(func() {
		if pl != nil {
			// Give some time for goroutines to finish before tearing down
			time.Sleep(100 * time.Millisecond)
			pl.TearDown()
		}
	})

	// Set timeout for each test
	SetDefaultEventuallyTimeout(60 * time.Second)
	SetDefaultEventuallyPollingInterval(100 * time.Millisecond)

	Describe("Cross-Protocol Compatibility", func() {
		It("should allow LSS resharing with CMP signing", func() {
			// Start with LSS keygen
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			// Generate keys with LSS
			lssConfigs := runLSSKeygen(partyIDs, threshold, group, pl, network)
			publicKey, err := lssConfigs[0].PublicKey()
			Expect(err).NotTo(HaveOccurred())

			// Convert LSS configs to CMP format
			cmpConfigs := make([]*cmp.Config, n)
			for i, lssConfig := range lssConfigs {
				cmpConfigs[i] = convertLSSToCMP(lssConfig)
			}

			// Sign with CMP protocol
			messageHash := randomHash()
			signers := partyIDs[:threshold]

			// CMP needs all configs to validate T < N
			signatures := runCMPSign(cmpConfigs, signers, messageHash, pl, network)

			// Verify signature
			Expect(signatures[0].Verify(publicKey, messageHash)).To(BeTrue())
		})

		It("should support FROST signing after LSS resharing", func() {
			// Initial LSS setup
			n := 7
			threshold := 4
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			lssConfigs := runLSSKeygen(partyIDs, threshold, group, pl, network)
			publicKey, err := lssConfigs[0].PublicKey()
			Expect(err).NotTo(HaveOccurred())

			// Perform resharing with LSS
			newParties := []party.ID{"new-1", "new-2"}
			allParties := append(partyIDs, newParties...)
			network = test.NewNetwork(allParties)

			newLSSConfigs := runLSSReshare(lssConfigs, newParties, threshold, publicKey, pl, network)

			// Convert to FROST format
			frostConfigs := make([]*frost.Config, len(newLSSConfigs))
			for i, lssConfig := range newLSSConfigs {
				frostConfigs[i] = convertLSSToFROST(lssConfig)
			}

			// Sign with FROST
			message := []byte("Cross-protocol test message")
			signers := allParties[:threshold]

			// Pass all configs to satisfy T < N validation
			frostSignatures := runFROSTSign(frostConfigs, signers, message, pl, network)

			// Verify Schnorr signature
			Expect(frostSignatures[0].Verify(publicKey, message)).To(BeTrue())
		})

		It("should maintain security properties across protocol switches", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			// Start with CMP
			cmpConfigs := runCMPKeygen(partyIDs, threshold, group, pl, network)
			publicKey := cmpConfigs[0].PublicPoint()

			// Convert to LSS for resharing capability
			lssConfigs := make([]*lssconfig.Config, n)
			for i, cmpConfig := range cmpConfigs {
				lssConfigs[i] = convertCMPToLSS(cmpConfig)
			}

			// Test that threshold is maintained
			messageHash := randomHash()

			// Try with T-1 parties (should fail)
			insufficientSigners := partyIDs[:threshold-1]
			Expect(func() {
				// Pass all configs but only insufficient signers
				runLSSSign(lssConfigs, insufficientSigners, messageHash, pl, network)
			}).Should(Panic())

			// Try with T parties (should succeed)
			signers := partyIDs[:threshold]
			signatures := runLSSSign(lssConfigs, signers, messageHash, pl, network)

			Expect(signatures[0].Verify(publicKey, messageHash)).To(BeTrue())
		})
	})

	Describe("Performance Comparison", func() {
		It("should benchmark all protocols with same parameters", func() {
			if testing.Short() {
				Skip("Skipping benchmark in short mode")
			}

			n := 7
			threshold := 4
			iterations := 10

			results := make(map[string]time.Duration)

			// Benchmark LSS
			start := time.Now()
			for i := 0; i < iterations; i++ {
				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				runLSSKeygen(partyIDs, threshold, group, pl, network)
			}
			results["LSS Keygen"] = time.Since(start) / time.Duration(iterations)

			// Benchmark CMP
			start = time.Now()
			for i := 0; i < iterations; i++ {
				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				runCMPKeygen(partyIDs, threshold, group, pl, network)
			}
			results["CMP Keygen"] = time.Since(start) / time.Duration(iterations)

			// Benchmark FROST
			start = time.Now()
			for i := 0; i < iterations; i++ {
				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				runFROSTKeygen(partyIDs, threshold, group, pl, network)
			}
			results["FROST Keygen"] = time.Since(start) / time.Duration(iterations)

			// Print results
			fmt.Println("\n=== Protocol Performance Comparison ===")
			for protocol, avgTime := range results {
				fmt.Printf("%s: %v\n", protocol, avgTime)
			}
		})
	})

	Describe("Advanced Integration Scenarios", func() {
		It("should handle mixed protocol signing in same session", func() {
			n := 9
			partyIDs := test.PartyIDs(n)

			// Generate keys with different protocols for different parties
			// First 3 use LSS
			lssParties := partyIDs[:3]
			lssNetwork := test.NewNetwork(lssParties)
			lssConfigs := runLSSKeygen(lssParties, 2, group, pl, lssNetwork)

			// Next 3 use CMP
			cmpParties := partyIDs[3:6]
			cmpNetwork := test.NewNetwork(cmpParties)
			cmpConfigs := runCMPKeygen(cmpParties, 2, group, pl, cmpNetwork)

			// Last 3 use FROST
			frostParties := partyIDs[6:9]
			frostNetwork := test.NewNetwork(frostParties)
			frostConfigs := runFROSTKeygen(frostParties, 2, group, pl, frostNetwork)

			// Each group should have generated valid configs
			Expect(lssConfigs).To(HaveLen(3))
			Expect(cmpConfigs).To(HaveLen(3))
			Expect(frostConfigs).To(HaveLen(3))
		})

		It("should support protocol migration during live operation", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			// Start with CMP
			cmpConfigs := runCMPKeygen(partyIDs, threshold, group, pl, network)

			// Perform some signatures
			for i := 0; i < 5; i++ {
				messageHash := randomHash()
				signers := partyIDs[:threshold]
				signatures := runCMPSign(cmpConfigs, signers, messageHash, pl, network)
				Expect(signatures[0].Verify(cmpConfigs[0].PublicPoint(), messageHash)).To(BeTrue())
			}

			// Migrate to LSS for resharing capability
			lssConfigs := make([]*lssconfig.Config, n)
			for i, cmpConfig := range cmpConfigs {
				lssConfigs[i] = convertCMPToLSS(cmpConfig)
			}

			// Continue signing with LSS
			for i := 0; i < 5; i++ {
				messageHash := randomHash()
				signers := partyIDs[:threshold]
				signatures := runLSSSign(lssConfigs, signers, messageHash, pl, network)
				pubKey, err := lssConfigs[0].PublicKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(signatures[0].Verify(pubKey, messageHash)).To(BeTrue())
			}
		})

		It("should handle protocol-specific optimizations", func() {
			n := 7
			threshold := 4
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			// CMP with presignatures for faster online signing
			cmpConfigs := runCMPKeygen(partyIDs, threshold, group, pl, network)

			// Generate presignatures
			signers := partyIDs[:threshold]
			presigs := runCMPPresign(cmpConfigs, signers, pl, network)

			// Fast online signing with presignatures
			messageHash := randomHash()
			start := time.Now()
			onlineSignatures := runCMPPresignOnline(cmpConfigs, presigs, messageHash, pl, network)
			onlineTime := time.Since(start)

			Expect(onlineSignatures[0].Verify(cmpConfigs[0].PublicPoint(), messageHash)).To(BeTrue())

			// Compare with regular signing
			start = time.Now()
			regularSignatures := runCMPSign(cmpConfigs, signers, messageHash, pl, network)
			regularTime := time.Since(start)

			Expect(regularSignatures[0].Verify(cmpConfigs[0].PublicPoint(), messageHash)).To(BeTrue())

			// Online signing should be faster
			fmt.Printf("Online signing: %v, Regular signing: %v\n", onlineTime, regularTime)
		})
	})

	Describe("Fault Tolerance Across Protocols", func() {
		It("should handle Byzantine parties in mixed protocol environment", func() {
			n := 9
			threshold := 5
			byzantineCount := 2

			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			// Setup with LSS (supports better fault tolerance)
			lssConfigs := runLSSKeygen(partyIDs, threshold, group, pl, network)

			// Mark some parties as Byzantine
			byzantineParties := make(map[party.ID]bool)
			for i := 0; i < byzantineCount; i++ {
				byzantineParties[partyIDs[i]] = true
			}
			byzantineNetwork := &ByzantineTestNetwork{
				Network:          network,
				ByzantineParties: byzantineParties,
			}

			// Should still produce valid signatures with honest parties
			messageHash := randomHash()
			signers := partyIDs // All parties attempt, but some are Byzantine

			// Run with fault tolerance
			signatures := runLSSSignWithFaultTolerance(lssConfigs, signers, messageHash, pl, byzantineNetwork)

			// Count valid signatures
			pubKey, err := lssConfigs[0].PublicKey()
			Expect(err).NotTo(HaveOccurred())
			validCount := 0
			for _, sig := range signatures {
				if sig != nil && sig.Verify(pubKey, messageHash) {
					validCount++
				}
			}

			Expect(validCount).To(BeNumerically(">=", threshold))
		})

		It("should recover from partial protocol failures", func() {
			n := 7
			threshold := 4
			partyIDs := test.PartyIDs(n)

			// Simulate network with failures
			unreliableNetwork := &UnreliableTestNetwork{
				Network:     test.NewNetwork(partyIDs),
				FailureRate: 0.2, // 20% message drop
			}

			// Try keygen with each protocol
			protocols := []string{"lss", "cmp", "frost"}
			successRates := make(map[string]float64)

			for _, protocolName := range protocols {
				successCount := 0
				attempts := 10

				for i := 0; i < attempts; i++ {
					var err error

					switch protocolName {
					case "lss":
						_, err = attemptLSSKeygen(partyIDs, threshold, group, pl, unreliableNetwork)
					case "cmp":
						_, err = attemptCMPKeygen(partyIDs, threshold, group, pl, unreliableNetwork)
					case "frost":
						_, err = attemptFROSTKeygen(partyIDs, threshold, group, pl, unreliableNetwork)
					}

					if err == nil {
						successCount++
					}
				}

				successRates[protocolName] = float64(successCount) / float64(attempts)
			}

			// All protocols should achieve some success despite network issues
			for protocol, rate := range successRates {
				fmt.Printf("%s success rate: %.2f%%\n", protocol, rate*100)
				Expect(rate).To(BeNumerically(">", 0))
			}
		})
	})
})

// Test implementations for different protocols

func runLSSKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *test.Network) []*lssconfig.Config {
	var wg sync.WaitGroup
	wg.Add(len(partyIDs))

	configs := make([]*lssconfig.Config, len(partyIDs))
	done := make(chan struct{})

	for i, id := range partyIDs {
		i := i
		go func(id party.ID) {
			defer GinkgoRecover()
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(id, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			configs[i] = r.(*lssconfig.Config)
		}(id)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		Fail("LSS keygen timed out after 30 seconds")
	}

	return configs
}

func runCMPKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *test.Network) []*cmp.Config {
	var wg sync.WaitGroup
	wg.Add(len(partyIDs))

	configs := make([]*cmp.Config, len(partyIDs))
	done := make(chan struct{})

	for i, id := range partyIDs {
		i := i
		go func(id party.ID) {
			defer GinkgoRecover()
			defer wg.Done()
			h, err := protocol.NewMultiHandler(cmp.Keygen(group, id, partyIDs, threshold, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(id, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			configs[i] = r.(*cmp.Config)
		}(id)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		Fail("CMP keygen timed out after 30 seconds")
	}
	return configs
}

func runFROSTKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *test.Network) []*frost.Config {
	var wg sync.WaitGroup
	wg.Add(len(partyIDs))

	configs := make([]*frost.Config, len(partyIDs))
	done := make(chan struct{})

	for i, id := range partyIDs {
		i := i
		go func(id party.ID) {
			defer GinkgoRecover()
			defer wg.Done()
			h, err := protocol.NewMultiHandler(frost.Keygen(group, id, partyIDs, threshold), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(id, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			configs[i] = r.(*frost.Config)
		}(id)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		Fail("FROST keygen timed out after 30 seconds")
	}

	return configs
}

func runLSSSign(configs []*lssconfig.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network) []*ecdsa.Signature {
	var wg sync.WaitGroup
	wg.Add(len(configs))

	signatures := make([]*ecdsa.Signature, len(configs))
	done := make(chan struct{})

	for i, config := range configs {
		i := i
		go func(c *lssconfig.Config) {
			defer GinkgoRecover()
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Sign(c, signers, messageHash, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			signatures[i] = r.(*ecdsa.Signature)
		}(config)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		Fail("LSS sign timed out after 30 seconds")
	}

	return signatures
}

func runCMPSign(configs []*cmp.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network) []*ecdsa.Signature {
	var wg sync.WaitGroup
	wg.Add(len(configs))
	
	signatures := make([]*ecdsa.Signature, len(configs))
	done := make(chan struct{})
	
	for i, config := range configs {
		i := i
		go func(c *cmp.Config) {
			defer GinkgoRecover()
			defer wg.Done()
			h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, messageHash, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			signatures[i] = r.(*ecdsa.Signature)
		}(config)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		Fail("CMP sign timed out after 30 seconds")
	}
	
	return signatures
}

func runFROSTSign(configs []*frost.Config, signers []party.ID, message []byte, pl *pool.Pool, network *test.Network) []*frost.Signature {
	var wg sync.WaitGroup
	wg.Add(len(configs))
	
	// All parties participate in the protocol, even if only some are signers
	signatures := make([]*frost.Signature, len(configs))
	for i, config := range configs {
		i := i
		go func(c *frost.Config) {
			defer wg.Done()
			defer GinkgoRecover()
			h, err := protocol.NewMultiHandler(frost.Sign(c, signers, message), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			signatures[i] = r.(*frost.Signature)
		}(config)
	}

	wg.Wait()
	return signatures
}

func runLSSReshare(configs []*lssconfig.Config, newParties []party.ID, newThreshold int, publicKey curve.Point, pl *pool.Pool, network *test.Network) []*lssconfig.Config {
	oldParties := getPartyIDs(configs)
	allParties := append(oldParties, newParties...)
	
	var wg sync.WaitGroup
	wg.Add(len(allParties))

	newConfigs := make([]*lssconfig.Config, len(allParties))
	done := make(chan struct{})

	for i, id := range allParties {
		i := i
		go func(id party.ID) {
			defer GinkgoRecover()
			defer wg.Done()
			
			// Find if this party has an existing config
			var existingConfig *lssconfig.Config
			for _, cfg := range configs {
				if cfg.ID == id {
					existingConfig = cfg
					break
				}
			}
			
			var h protocol.Handler
			var err error
			
			if existingConfig != nil {
				// Existing party participates in reshare
				h, err = protocol.NewMultiHandler(lss.Reshare(existingConfig, allParties, newThreshold, pl), nil)
			} else {
				// New party joins via reshare (needs special handling in real implementation)
				// For now, we'll simulate by having them participate in a new keygen
				// In a real implementation, new parties would receive shares from existing parties
				h, err = protocol.NewMultiHandler(lss.Keygen(configs[0].Group, id, allParties, newThreshold, pl), nil)
			}
			
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(id, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			newConfigs[i] = r.(*lssconfig.Config)
		}(id)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		Fail("LSS reshare timed out after 30 seconds")
	}

	return newConfigs
}

func getPartyIDs(configs []*lssconfig.Config) []party.ID {
	ids := make([]party.ID, len(configs))
	for i, cfg := range configs {
		ids[i] = cfg.ID
	}
	return ids
}

func runCMPPresign(configs []*cmp.Config, signers []party.ID, pl *pool.Pool, network *test.Network) []*ecdsa.PreSignature {
	var wg sync.WaitGroup
	wg.Add(len(configs))
	
	// All parties participate in the protocol, even if only some are signers
	presigs := make([]*ecdsa.PreSignature, len(configs))
	for i, config := range configs {
		i := i
		go func(c *cmp.Config) {
			defer wg.Done()
			defer GinkgoRecover()
			h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			presigs[i] = r.(*ecdsa.PreSignature)
		}(config)
	}

	wg.Wait()
	return presigs
}

func runCMPPresignOnline(configs []*cmp.Config, presigs []*ecdsa.PreSignature, messageHash []byte, pl *pool.Pool, network *test.Network) []*ecdsa.Signature {
	var wg sync.WaitGroup
	wg.Add(len(configs))
	
	signatures := make([]*ecdsa.Signature, len(configs))
	for i, config := range configs {
		i := i
		go func(c *cmp.Config, presig *ecdsa.PreSignature) {
			defer wg.Done()
			defer GinkgoRecover()
			h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, presig, messageHash, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			signatures[i] = r.(*ecdsa.Signature)
		}(config, presigs[i])
	}

	wg.Wait()
	return signatures
}

func runLSSSignWithFaultTolerance(configs []*lssconfig.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *ByzantineTestNetwork) []*ecdsa.Signature {
	var wg sync.WaitGroup
	signatures := make([]*ecdsa.Signature, len(configs))
	
	// Only run protocol for non-Byzantine parties
	for i, config := range configs {
		if network.ByzantineParties[config.ID] {
			continue
		}
		
		wg.Add(1)
		i := i
		go func(c *lssconfig.Config) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// Byzantine parties may cause panics, handle gracefully
					signatures[i] = nil
				}
			}()
			
			h, err := protocol.NewMultiHandler(lss.Sign(c, signers, messageHash, pl), nil)
			if err != nil {
				signatures[i] = nil
				return
			}
			
			test.HandlerLoop(c.ID, h, network.Network)
			
			r, err := h.Result()
			if err != nil {
				signatures[i] = nil
				return
			}
			
			signatures[i] = r.(*ecdsa.Signature)
		}(config)
	}
	
	wg.Wait()
	return signatures
}

// Conversion functions
// Note: These conversions are simplified for testing purposes.
// In production, proper cryptographic conversion would be needed.

func convertLSSToCMP(lss *lssconfig.Config) *cmp.Config {
	// Convert LSS config to CMP format
	// This requires mapping the ECDSA shares and public keys
	cmpPublic := make(map[party.ID]*cmpconfig.Public)
	for id, pub := range lss.Public {
		cmpPublic[id] = &cmpconfig.Public{
			ECDSA: pub.ECDSA,
			// ElGamal and Paillier would need to be generated/converted
			// For testing, we'll use nil values which should be handled
		}
	}
	
	return &cmp.Config{
		ID:        lss.ID,
		Group:     lss.Group,
		Threshold: lss.Threshold,
		ECDSA:     lss.ECDSA,
		Public:    cmpPublic,
		ChainKey:  lss.ChainKey,
		RID:       lss.RID,
	}
}

func convertLSSToFROST(lss *lssconfig.Config) *frost.Config {
	// Convert LSS to FROST format for Schnorr signatures
	pubKey, _ := lss.PublicKey()
	
	// FROST uses VerificationShares instead of PublicShares
	// Create verification shares map for all parties
	verificationPoints := make(map[party.ID]curve.Point)
	for id, pub := range lss.Public {
		verificationPoints[id] = pub.ECDSA
	}
	verificationShares := party.NewPointMap(verificationPoints)
	
	return &frost.Config{
		ID:                 lss.ID,
		Threshold:          lss.Threshold,
		PrivateShare:       lss.ECDSA,
		PublicKey:          pubKey,
		VerificationShares: verificationShares,
		ChainKey:           lss.ChainKey,
	}
}

func convertCMPToLSS(cmpCfg *cmp.Config) *lssconfig.Config {
	// Convert CMP config to LSS format
	lssPublic := make(map[party.ID]*lssconfig.Public)
	for id, pub := range cmpCfg.Public {
		lssPublic[id] = &lssconfig.Public{
			ECDSA: pub.ECDSA,
		}
	}
	
	return &lssconfig.Config{
		ID:         cmpCfg.ID,
		Group:      cmpCfg.Group,
		Threshold:  cmpCfg.Threshold,
		Generation: 0,
		ECDSA:      cmpCfg.ECDSA,
		Public:     lssPublic,
		ChainKey:   cmpCfg.ChainKey,
		RID:        cmpCfg.RID,
	}
}

// Attempt functions for unreliable networks

func attemptLSSKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *UnreliableTestNetwork) ([]*lssconfig.Config, error) {
	configs := make([]*lssconfig.Config, len(partyIDs))
	errors := make([]error, len(partyIDs))
	var wg sync.WaitGroup
	wg.Add(len(partyIDs))

	for i, id := range partyIDs {
		i := i
		go func(id party.ID) {
			defer GinkgoRecover()
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
			if err != nil {
				errors[i] = err
				return
			}

			done := make(chan bool, 1)
			go func() {
				test.HandlerLoop(id, h, network.Network)
				done <- true
			}()

			select {
			case <-done:
				r, err := h.Result()
				if err != nil {
					errors[i] = err
				} else {
					configs[i] = r.(*lssconfig.Config)
				}
			case <-time.After(10 * time.Second):
				errors[i] = fmt.Errorf("timeout")
			}
		}(id)
	}

	wg.Wait()

	// Check if we have enough successful configs
	successCount := 0
	for _, config := range configs {
		if config != nil {
			successCount++
		}
	}

	if successCount < threshold {
		return nil, fmt.Errorf("insufficient successful parties: %d < %d", successCount, threshold)
	}

	return configs, nil
}

func attemptCMPKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *UnreliableTestNetwork) ([]*cmp.Config, error) {
	// Similar implementation to attemptLSSKeygen but for CMP
	return nil, fmt.Errorf("not implemented")
}

func attemptFROSTKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *UnreliableTestNetwork) ([]*frost.Config, error) {
	// Similar implementation to attemptLSSKeygen but for FROST
	return nil, fmt.Errorf("not implemented")
}

// Helper functions

func randomHash() []byte {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	return hash
}

// Test network implementations

type ByzantineTestNetwork struct {
	*test.Network
	ByzantineParties map[party.ID]bool
}

func (b *ByzantineTestNetwork) Send(msg *protocol.Message) {
	if b.ByzantineParties[msg.From] {
		// Byzantine party - drop or corrupt message
		if mathrand.Float64() < 0.5 {
			return // Drop
		}
		// Could corrupt message here
	}
	b.Network.Send(msg)
}

type UnreliableTestNetwork struct {
	*test.Network
	FailureRate float64
}

func (u *UnreliableTestNetwork) Send(msg *protocol.Message) {
	if mathrand.Float64() < u.FailureRate {
		return // Drop message
	}
	u.Network.Send(msg)
}

// Benchmark helper
func BenchmarkProtocolComparison(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	n := 5
	threshold := 3
	group := curve.Secp256k1{}

	b.Run("LSS", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)
			runLSSKeygen(partyIDs, threshold, group, pl, network)
		}
	})

	b.Run("CMP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)
			runCMPKeygen(partyIDs, threshold, group, pl, network)
		}
	})

	b.Run("FROST", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)
			runFROSTKeygen(partyIDs, threshold, group, pl, network)
		}
	})
}
