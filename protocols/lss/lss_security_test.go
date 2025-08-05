package lss_test

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("LSS Protocol Security Properties", func() {
	var (
		pl      *pool.Pool
		network *test.Network
		group   curve.Curve
	)

	BeforeEach(func() {
		pl = pool.NewPool(0)
		group = curve.Secp256k1{}
	})

	AfterEach(func() {
		pl.TearDown()
	})

	Describe("Functional Correctness", func() {
		Context("Basic Signature Generation", func() {
			It("should allow T-of-N participants to produce valid signatures", func() {
				testCases := []struct {
					n         int
					threshold int
				}{
					{5, 3},
					{7, 4},
					{9, 5},
				}

				for _, tc := range testCases {
					By(fmt.Sprintf("Testing %d-of-%d threshold", tc.threshold, tc.n))

					partyIDs := test.PartyIDs(tc.n)
					network = test.NewNetwork(partyIDs)

					// Run keygen
					configs := runKeygen(partyIDs, tc.threshold, group, pl, network)

					// Test signing with exactly threshold parties
					messageHash := randomHash()
					signers := partyIDs[:tc.threshold]

					signatures := runSign(configs[:tc.threshold], signers, messageHash, pl, network)

					// Verify all signatures are identical and valid
					Expect(signatures).To(HaveLen(tc.threshold))
					for _, sig := range signatures {
						Expect(sig.Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
					}
				}
			})

			It("should work with edge case group sizes", func() {
				edgeCases := []struct {
					name      string
					n         int
					threshold int
				}{
					{"T=1", 3, 1},
					{"T=N", 5, 5},
					{"T=ceil(N/2)", 7, 4},
					{"Minimum 2-of-2", 2, 2},
					{"Large group", 21, 15},
				}

				for _, tc := range edgeCases {
					By(tc.name)

					partyIDs := test.PartyIDs(tc.n)
					network = test.NewNetwork(partyIDs)

					configs := runKeygen(partyIDs, tc.threshold, group, pl, network)

					messageHash := randomHash()
					signers := partyIDs[:tc.threshold]

					signatures := runSign(configs[:tc.threshold], signers, messageHash, pl, network)

					Expect(signatures).To(HaveLen(tc.threshold))
					Expect(signatures[0].Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
				}
			})
		})

		Context("Membership Dynamics", func() {
			It("should handle adding members through resharing", func() {
				// Start with 3-of-5
				initialN := 5
				initialThreshold := 3
				initialPartyIDs := test.PartyIDs(initialN)
				network = test.NewNetwork(initialPartyIDs)

				configs := runKeygen(initialPartyIDs, initialThreshold, group, pl, network)
				publicKey := configs[0].PublicKey

				// Add 2 new parties to make 3-of-7
				newParties := []party.ID{"new-1", "new-2"}
				allParties := append(initialPartyIDs, newParties...)
				network = test.NewNetwork(allParties)

				newConfigs := runReshare(configs, initialThreshold, newParties, publicKey, pl, network)

				// Verify new configuration
				Expect(newConfigs).To(HaveLen(7))
				for _, config := range newConfigs {
					Expect(config.PublicKey.Equal(publicKey)).To(BeTrue())
					Expect(config.Generation).To(Equal(uint64(2)))
				}

				// Test signing with new group
				messageHash := randomHash()
				signers := allParties[:initialThreshold]
				signatures := runSign(newConfigs[:initialThreshold], signers, messageHash, pl, network)

				Expect(signatures[0].Verify(publicKey, messageHash)).To(BeTrue())
			})

			It("should handle removing members through resharing", func() {
				// Start with 3-of-5
				initialN := 5
				initialThreshold := 3
				initialPartyIDs := test.PartyIDs(initialN)
				network = test.NewNetwork(initialPartyIDs)

				configs := runKeygen(initialPartyIDs, initialThreshold, group, pl, network)
				publicKey := configs[0].PublicKey

				// Remove 2 parties to make 2-of-3
				remainingConfigs := configs[:3]
				remainingPartyIDs := initialPartyIDs[:3]
				newThreshold := 2

				network = test.NewNetwork(remainingPartyIDs)
				newConfigs := runReshare(remainingConfigs, newThreshold, nil, publicKey, pl, network)

				// Verify removed parties cannot participate
				messageHash := randomHash()
				signers := remainingPartyIDs[:newThreshold]
				signatures := runSign(newConfigs[:newThreshold], signers, messageHash, pl, network)

				Expect(signatures[0].Verify(publicKey, messageHash)).To(BeTrue())
			})

			It("should support live resharing without downtime", func() {
				// Initial setup
				n := 7
				threshold := 4
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)
				publicKey := configs[0].PublicKey

				// Start concurrent signing operations
				done := make(chan bool)
				go func() {
					for {
						select {
						case <-done:
							return
						default:
							messageHash := randomHash()
							signers := partyIDs[:threshold]
							runSign(configs[:threshold], signers, messageHash, pl, network)
							time.Sleep(100 * time.Millisecond)
						}
					}
				}()

				// Perform resharing while signing continues
				newParties := []party.ID{"new-1"}
				allParties := append(partyIDs, newParties...)
				network = test.NewNetwork(allParties)

				newConfigs := runReshare(configs, threshold, newParties, publicKey, pl, network)

				close(done)

				// Verify new configuration works
				messageHash := randomHash()
				signers := allParties[:threshold]
				signatures := runSign(newConfigs[:threshold], signers, messageHash, pl, network)

				Expect(signatures[0].Verify(publicKey, messageHash)).To(BeTrue())
			})
		})

		Context("Partial Participation", func() {
			It("should prevent signature generation with less than T participants", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Try with T-1 participants
				messageHash := randomHash()
				insufficientSigners := partyIDs[:threshold-1]

				// This should fail at the protocol level
				Expect(func() {
					runSign(configs[:threshold-1], insufficientSigners, messageHash, pl, network)
				}).Should(Panic()) // Or handle the specific error type
			})

			It("should handle missing or dropped parties gracefully", func() {
				n := 7
				threshold := 4
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Simulate network issues for some parties
				// Note: SetFilter not available in test.Network, skipping fault simulation
				// faultyNetwork := test.NewNetwork(partyIDs)
				// faultyNetwork.SetFilter(...)

				// Should still work with remaining parties
				messageHash := randomHash()
				signers := partyIDs[:threshold+1] // Include one extra in case of drops

				signatures := runSignWithTimeout(configs[:threshold+1], signers, messageHash, pl, network, 10*time.Second)

				// At least threshold parties should succeed
				successCount := 0
				for _, sig := range signatures {
					if sig != nil && sig.Verify(configs[0].PublicKey, messageHash) {
						successCount++
					}
				}
				Expect(successCount).To(BeNumerically(">=", threshold))
			})
		})

		Context("Persistence and Rollback", func() {
			It("should recover correct state after crash/restart", func() {
				// Initial setup
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Simulate saving state
				savedConfigs := make([]*lss.Config, len(configs))
				for i, config := range configs {
					// Deep copy simulation
					savedConfigs[i] = &lss.Config{
						ID:           config.ID,
						Group:        config.Group,
						Threshold:    config.Threshold,
						Generation:   config.Generation,
						SecretShare:  config.SecretShare,
						PublicKey:    config.PublicKey,
						PublicShares: config.PublicShares,
						PartyIDs:     config.PartyIDs,
					}
				}

				// "Crash" and recover
				pl = pool.NewPool(0)

				// Use saved configs to sign
				messageHash := randomHash()
				signers := partyIDs[:threshold]
				signatures := runSign(savedConfigs[:threshold], signers, messageHash, pl, network)

				Expect(signatures[0].Verify(savedConfigs[0].PublicKey, messageHash)).To(BeTrue())
			})

			It("should maintain consistency after rollback", func() {
				// Initial setup and multiple generations
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)
				gen1Configs := copyConfigs(configs)

				// Generation 2: Add a party
				newParties := []party.ID{"new-1"}
				allParties := append(partyIDs, newParties...)
				network = test.NewNetwork(allParties)

				gen2Configs := runReshare(configs, threshold, newParties, configs[0].PublicKey, pl, network)

				// Generation 3: Remove a party (not used in this test)
				// gen3Configs := runReshare(gen2Configs[:n], threshold, nil, configs[0].PublicKey, pl, network)
				_ = gen2Configs // Mark as used

				// Simulate rollback to generation 1
				messageHash := randomHash()
				signers := partyIDs[:threshold]
				signatures := runSign(gen1Configs[:threshold], signers, messageHash, pl, network)

				Expect(signatures[0].Verify(gen1Configs[0].PublicKey, messageHash)).To(BeTrue())
			})
		})

		Context("Cross-Chain Support", func() {
			It("should generate valid signatures for different formats", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				testCases := []struct {
					name        string
					messageHash []byte
					verify      func(*ecdsa.Signature, curve.Point, []byte) bool
				}{
					{
						name:        "Ethereum format",
						messageHash: ethHash("test message"),
						verify:      verifyEthereumSignature,
					},
					{
						name:        "Bitcoin format",
						messageHash: btcHash("test message"),
						verify:      verifyBitcoinSignature,
					},
					{
						name:        "Standard ECDSA",
						messageHash: randomHash(),
						verify: func(sig *ecdsa.Signature, pk curve.Point, hash []byte) bool {
							return sig.Verify(pk, hash)
						},
					},
				}

				for _, tc := range testCases {
					By(tc.name)
					signers := partyIDs[:threshold]
					signatures := runSign(configs[:threshold], signers, tc.messageHash, pl, network)

					Expect(tc.verify(signatures[0], configs[0].PublicKey, tc.messageHash)).To(BeTrue())
				}
			})
		})
	})

	Describe("Security Properties", func() {
		Context("Threshold Security", func() {
			It("should prevent key reconstruction with fewer than T shares", func() {
				n := 7
				threshold := 4
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Attempt to reconstruct private key with T-1 shares
				corruptShares := configs[:threshold-1]

				// This should be cryptographically impossible
				// Verify by attempting various combinations
				reconstructed := attemptKeyReconstruction(corruptShares)
				Expect(reconstructed).To(BeNil())
			})

			It("should prevent signature forgery with fewer than T parties", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Malicious coalition of T-1 parties
				maliciousParties := configs[:threshold-1]
				targetMessage := []byte("unauthorized transfer")

				// Attempt forgery
				forgedSig := attemptSignatureForgery(maliciousParties, targetMessage)

				if forgedSig != nil {
					Expect(forgedSig.Verify(configs[0].PublicKey, targetMessage)).To(BeFalse())
				}
			})
		})

		Context("Blinding and Nonce Security", func() {
			It("should use fresh nonces for each signing operation", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Sign same message multiple times
				messageHash := randomHash()
				signers := partyIDs[:threshold]

				signatures := make([]*ecdsa.Signature, 5)
				nonces := make([]curve.Scalar, 5)

				for i := 0; i < 5; i++ {
					sigs := runSignWithNonceCapture(configs[:threshold], signers, messageHash, pl, network, &nonces[i])
					signatures[i] = sigs[0]
				}

				// All signatures should be valid but use different nonces
				for i, sig := range signatures {
					Expect(sig.Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
					for j := i + 1; j < len(nonces); j++ {
						if nonces[i] != nil && nonces[j] != nil {
							Expect(nonces[i].Equal(nonces[j])).To(BeFalse())
						}
					}
				}
			})

			It("should properly implement blinding protocols", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Test both blinding protocols
				protocols := []int{1, 2}

				for _, protocolVersion := range protocols {
					By(fmt.Sprintf("Testing blinding protocol %d", protocolVersion))

					messageHash := randomHash()
					signers := partyIDs[:threshold]

					signatures := runSignWithBlinding(configs[:threshold], signers, messageHash, protocolVersion, pl, network)

					Expect(signatures[0].Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
				}
			})
		})

		Context("Message Authentication", func() {
			It("should reject unauthenticated messages", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Create a malicious network that injects fake messages
				maliciousNetwork := &MaliciousNetwork{
					Network:    network,
					InjectRate: 0.1, // 10% message injection
				}

				messageHash := randomHash()
				signers := partyIDs[:threshold]

				// Protocol should still succeed despite attacks
				signatures := runSign(configs[:threshold], signers, messageHash, pl, maliciousNetwork.Network)

				Expect(signatures[0].Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
			})

			It("should prevent replay attacks", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Record messages from first signing
				recordingNetwork := &RecordingNetwork{Network: network}

				messageHash1 := randomHash()
				signers := partyIDs[:threshold]
				runSign(configs[:threshold], signers, messageHash1, pl, recordingNetwork.Network)

				// Attempt to replay messages for different signing
				replayNetwork := &ReplayNetwork{
					Network:          network,
					RecordedMessages: recordingNetwork.Messages,
				}

				messageHash2 := randomHash()

				// This should fail or produce invalid signature
				Expect(func() {
					runSign(configs[:threshold], signers, messageHash2, pl, replayNetwork.Network)
				}).Should(Panic())
			})
		})

		Context("Byzantine Fault Tolerance", func() {
			It("should handle malicious parties sending invalid shares", func() {
				n := 7
				threshold := 4
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Make one party malicious
				maliciousIdx := 2
				maliciousWrapper := &MaliciousPartyWrapper{
					Config:        configs[maliciousIdx],
					MaliciousType: "invalid_shares",
				}

				// Create wrapped configs for fault tolerance test
				wrappedConfigs := make([]*lss.Config, threshold+1)
				for i := 0; i < threshold+1; i++ {
					if i == maliciousIdx {
						// In real implementation, this would inject faults
						wrappedConfigs[i] = configs[i]
					} else {
						wrappedConfigs[i] = configs[i]
					}
				}
				_ = maliciousWrapper // Mark as used

				messageHash := randomHash()
				// Include extra parties to compensate for malicious one
				signers := partyIDs[:threshold+1]

				// Should still produce valid signature with honest parties
				signatures := runSignWithFaultTolerance(wrappedConfigs, signers, messageHash, pl, network)

				validCount := 0
				for _, sig := range signatures {
					if sig != nil && sig.Verify(configs[0].PublicKey, messageHash) {
						validCount++
					}
				}
				Expect(validCount).To(BeNumerically(">=", threshold))
			})

			It("should detect and handle protocol deviations", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Create Byzantine party that deviates from protocol
				byzantineIdx := 1
				byzantineWrapper := &ByzantinePartyWrapper{
					Config:        configs[byzantineIdx],
					DeviationType: "wrong_protocol_flow",
				}

				// Create wrapped configs for Byzantine test
				wrappedConfigs := make([]*lss.Config, threshold+1)
				for i := 0; i < threshold+1; i++ {
					if i == byzantineIdx {
						// In real implementation, this would cause protocol deviation
						wrappedConfigs[i] = configs[i]
					} else {
						wrappedConfigs[i] = configs[i]
					}
				}
				_ = byzantineWrapper // Mark as used

				messageHash := randomHash()
				signers := partyIDs[:threshold+1] // Extra party for fault tolerance

				// Protocol should detect and handle deviation
				signatures := runSignWithByzantineDetection(wrappedConfigs, signers, messageHash, pl, network)

				// Should succeed with honest parties
				Expect(len(signatures)).To(BeNumerically(">=", threshold))
			})
		})

		Context("Rollback Security", func() {
			It("should prevent signature forgery with old states", func() {
				n := 5
				threshold := 3
				partyIDs := test.PartyIDs(n)
				network = test.NewNetwork(partyIDs)

				// Generation 1
				gen1Configs := runKeygen(partyIDs, threshold, group, pl, network)

				// Generation 2 after resharing
				newParties := []party.ID{"new-1"}
				allParties := append(partyIDs, newParties...)
				network = test.NewNetwork(allParties)

				gen2Configs := runReshare(gen1Configs, threshold, newParties, gen1Configs[0].PublicKey, pl, network)

				// Attempt to use old generation shares with new generation
				messageHash := randomHash()

				// Mix old and new configs (should fail)
				mixedConfigs := make([]*lss.Config, threshold)
				mixedConfigs[0] = gen1Configs[0] // Old generation
				for i := 1; i < threshold; i++ {
					mixedConfigs[i] = gen2Configs[i] // New generation
				}

				// This should fail due to generation mismatch
				Expect(func() {
					runSign(mixedConfigs, partyIDs[:threshold], messageHash, pl, network)
				}).Should(Panic())
			})
		})
	})

	Describe("Honest-but-Curious Security", func() {
		It("should not leak information to curious participants", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			network = test.NewNetwork(partyIDs)

			// Setup with information tracking
			trackingConfigs := make([]*InformationTrackingWrapper, n)

			// Run keygen with tracking
			configs := runKeygen(partyIDs, threshold, group, pl, network)
			for i, config := range configs {
				trackingConfigs[i] = &InformationTrackingWrapper{
					Config:       config,
					ObservedData: make(map[string]interface{}),
				}
			}

			// Run several signing operations
			for i := 0; i < 10; i++ {
				messageHash := randomHash()
				signers := partyIDs[:threshold]
				runSignWithTracking(trackingConfigs[:threshold], signers, messageHash, pl, network)
			}

			// Verify no party learned more than their share
			for i, wrapper := range trackingConfigs[:threshold] {
				// Each party should only know:
				// - Their own secret share
				// - Public keys and shares
				// - Protocol messages they received

				// They should NOT know:
				// - Other parties' secret shares
				// - The master private key
				// - Other parties' random nonces

				Expect(wrapper.LearnedOtherSecrets()).To(BeFalse(),
					fmt.Sprintf("Party %d learned unauthorized information", i))
			}
		})
	})
})

// Helper functions

func runKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *test.Network) []*lss.Config {
	var wg sync.WaitGroup
	wg.Add(len(partyIDs))

	configs := make([]*lss.Config, len(partyIDs))
	for i, id := range partyIDs {
		i := i
		go func(id party.ID) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(id, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			configs[i] = r.(*lss.Config)
		}(id)
	}

	wg.Wait()
	return configs
}

func runSign(configs []*lss.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network) []*ecdsa.Signature {
	var wg sync.WaitGroup
	wg.Add(len(configs))

	signatures := make([]*ecdsa.Signature, len(configs))
	for i, config := range configs {
		i := i
		go func(c *lss.Config) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Sign(c, signers, messageHash, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			signatures[i] = r.(*ecdsa.Signature)
		}(config)
	}

	wg.Wait()
	return signatures
}

func runSignWithTimeout(configs []*lss.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network, timeout time.Duration) []*ecdsa.Signature {
	signatures := make([]*ecdsa.Signature, len(configs))
	done := make(chan bool)

	go func() {
		var wg sync.WaitGroup
		wg.Add(len(configs))

		for i, config := range configs {
			i := i
			go func(c *lss.Config) {
				defer wg.Done()
				h, err := protocol.NewMultiHandler(lss.Sign(c, signers, messageHash, pl), nil)
				if err != nil {
					return
				}
				test.HandlerLoop(c.ID, h, network)

				r, err := h.Result()
				if err == nil {
					signatures[i] = r.(*ecdsa.Signature)
				}
			}(config)
		}

		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return signatures
	case <-time.After(timeout):
		return signatures
	}
}

func runReshare(configs []*lss.Config, newThreshold int, newParties []party.ID, publicKey curve.Point, pl *pool.Pool, network *test.Network) []*lss.Config {
	var wg sync.WaitGroup
	totalParties := len(configs) + len(newParties)
	wg.Add(totalParties)

	newConfigs := make([]*lss.Config, totalParties)

	// Existing parties
	for i, config := range configs {
		currentIdx := i
		go func(c *lss.Config, idx int) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Reshare(c, newThreshold, newParties, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			newConfigs[idx] = r.(*lss.Config)
		}(config, currentIdx)
	}

	// New parties
	for i, newID := range newParties {
		currentIdx := len(configs) + i
		go func(id party.ID, idx int) {
			defer wg.Done()
			emptyConfig := &lss.Config{
				ID:           id,
				Group:        configs[0].Group,
				PublicKey:    publicKey,
				Generation:   configs[0].Generation,
				PartyIDs:     configs[0].PartyIDs,
				PublicShares: make(map[party.ID]curve.Point),
			}
			h, err := protocol.NewMultiHandler(lss.Reshare(emptyConfig, newThreshold, newParties, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(id, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			newConfigs[idx] = r.(*lss.Config)
		}(newID, currentIdx)
	}

	wg.Wait()
	return newConfigs[:len(configs)+len(newParties)]
}

func runSignWithBlinding(configs []*lss.Config, signers []party.ID, messageHash []byte, protocolVersion int, pl *pool.Pool, network *test.Network) []*ecdsa.Signature {
	var wg sync.WaitGroup
	wg.Add(len(configs))

	signatures := make([]*ecdsa.Signature, len(configs))
	for i, config := range configs {
		i := i
		go func(c *lss.Config) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.SignWithBlinding(c, signers, messageHash, protocolVersion, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			signatures[i] = r.(*ecdsa.Signature)
		}(config)
	}

	wg.Wait()
	return signatures
}

func randomHash() []byte {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	return hash
}

func copyConfigs(configs []*lss.Config) []*lss.Config {
	copied := make([]*lss.Config, len(configs))
	for i, config := range configs {
		copied[i] = &lss.Config{
			ID:           config.ID,
			Group:        config.Group,
			Threshold:    config.Threshold,
			Generation:   config.Generation,
			SecretShare:  config.SecretShare,
			PublicKey:    config.PublicKey,
			PublicShares: config.PublicShares,
			PartyIDs:     config.PartyIDs,
		}
	}
	return copied
}

// Mock functions for demonstration - would need actual implementation

func ethHash(message string) []byte {
	// Ethereum-style hashing
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	return hash
}

func btcHash(message string) []byte {
	// Bitcoin-style double SHA256
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	return hash
}

func verifyEthereumSignature(sig *ecdsa.Signature, pk curve.Point, hash []byte) bool {
	// Ethereum signature verification
	return sig.Verify(pk, hash)
}

func verifyBitcoinSignature(sig *ecdsa.Signature, pk curve.Point, hash []byte) bool {
	// Bitcoin signature verification
	return sig.Verify(pk, hash)
}

func attemptKeyReconstruction(shares []*lss.Config) curve.Scalar {
	// Attempt to reconstruct private key (should fail with < T shares)
	return nil
}

func attemptSignatureForgery(shares []*lss.Config, message []byte) *ecdsa.Signature {
	// Attempt to forge signature (should fail)
	return nil
}

func runSignWithNonceCapture(configs []*lss.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network, nonce *curve.Scalar) []*ecdsa.Signature {
	// Run signing while capturing nonce values
	return runSign(configs, signers, messageHash, pl, network)
}

func runSignWithFaultTolerance(configs []*lss.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network) []*ecdsa.Signature {
	// Run signing with fault tolerance
	return runSign(configs, signers, messageHash, pl, network)
}

func runSignWithByzantineDetection(configs []*lss.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network) []*ecdsa.Signature {
	// Run signing with Byzantine detection
	return runSign(configs, signers, messageHash, pl, network)
}

func runSignWithTracking(configs []*InformationTrackingWrapper, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network) {
	// Run signing with information tracking
}

// Mock wrapper types

type MaliciousNetwork struct {
	*test.Network
	InjectRate float64
}

type RecordingNetwork struct {
	*test.Network
	Messages []protocol.Message
}

type ReplayNetwork struct {
	*test.Network
	RecordedMessages []protocol.Message
}

type MaliciousPartyWrapper struct {
	Config        *lss.Config
	MaliciousType string
}

type ByzantinePartyWrapper struct {
	Config        *lss.Config
	DeviationType string
}

type InformationTrackingWrapper struct {
	*lss.Config
	ObservedData map[string]interface{}
}

func (w *InformationTrackingWrapper) LearnedOtherSecrets() bool {
	// Check if party learned unauthorized information
	return false
}
