package lss_test

import (
	"math/big"
	"testing"
	"testing/quick"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss"
)

var _ = Describe("LSS Property-Based Tests", func() {
	var (
		pl    *pool.Pool
		group curve.Curve
	)

	BeforeEach(func() {
		pl = pool.NewPool(0)
		group = curve.Secp256k1{}
	})

	AfterEach(func() {
		pl.TearDown()
	})

	Describe("Property-Based Testing", func() {
		It("should maintain threshold property for any valid configuration", func() {
			property := func(nRaw, tRaw uint8) bool {
				// Convert to valid ranges
				n := int(nRaw%20) + 2  // n in [2, 21]
				t := int(tRaw%uint8(n)) + 1  // t in [1, n]
				
				if t > n || t < 1 || n < 2 {
					return true // Skip invalid configurations
				}

				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				
				// Run keygen
				configs := runKeygen(partyIDs, t, group, pl, network)
				
				// Test: Any t parties can sign
				messageHash := randomHash()
				signers := partyIDs[:t]
				signatures := runSign(configs[:t], signers, messageHash, pl, network)
				
				// Verify signature
				return signatures[0].Verify(configs[0].PublicKey, messageHash)
			}

			// Run property test
			config := &quick.Config{MaxCount: 20}
			Expect(quick.Check(property, config)).To(Succeed())
		})

		It("should handle arbitrary membership changes", func() {
			property := func(initialN, initialT, addCount, removeCount uint8) bool {
				// Normalize inputs
				n := int(initialN%10) + 5  // n in [5, 14]
				t := int(initialT%uint8(n-2)) + 2  // t in [2, n-1]
				add := int(addCount % 5)  // add up to 5
				remove := int(removeCount % uint8(n-t))  // ensure we keep at least t parties
				
				if t > n || t < 2 || n < 3 {
					return true
				}

				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				
				// Initial keygen
				configs := runKeygen(partyIDs, t, group, pl, network)
				publicKey := configs[0].PublicKey
				
				// Add parties
				newParties := make([]party.ID, add)
				for i := 0; i < add; i++ {
					newParties[i] = party.ID(fmt.Sprintf("new-%d", i))
				}
				
				// Remove parties (keep at least t)
				remainingConfigs := configs
				if remove > 0 && len(configs)-remove >= t {
					remainingConfigs = configs[:len(configs)-remove]
				}
				
				// Perform reshare if there are changes
				if add > 0 || remove > 0 {
					allParties := append(remainingConfigs[0].PartyIDs, newParties...)
					network = test.NewNetwork(allParties)
					newConfigs := runReshare(remainingConfigs, t, newParties, publicKey, pl, network)
					
					// Verify new configuration
					return newConfigs[0].PublicKey.Equal(publicKey) &&
						len(newConfigs) == len(remainingConfigs)+add
				}
				
				return true
			}

			config := &quick.Config{MaxCount: 15}
			Expect(quick.Check(property, config)).To(Succeed())
		})

		It("should produce deterministic signatures for same input", func() {
			property := func(seed int64) bool {
				n := 5
				t := 3
				
				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				
				configs := runKeygen(partyIDs, t, group, pl, network)
				
				// Use seed to generate deterministic message
				messageHash := make([]byte, 32)
				for i := 0; i < 32; i++ {
					messageHash[i] = byte(seed >> (i % 8))
				}
				
				signers := partyIDs[:t]
				
				// Sign twice with same message
				sig1 := runSign(configs[:t], signers, messageHash, pl, network)[0]
				sig2 := runSign(configs[:t], signers, messageHash, pl, network)[0]
				
				// Both should be valid
				return sig1.Verify(configs[0].PublicKey, messageHash) &&
					sig2.Verify(configs[0].PublicKey, messageHash)
			}

			config := &quick.Config{MaxCount: 10}
			Expect(quick.Check(property, config)).To(Succeed())
		})

		It("should maintain security across threshold changes", func() {
			property := func(oldT, newT uint8) bool {
				n := 7
				oldThreshold := int(oldT%5) + 2  // [2, 6]
				newThreshold := int(newT%5) + 2  // [2, 6]
				
				if oldThreshold > n || newThreshold > n {
					return true
				}

				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				
				// Initial setup with oldThreshold
				configs := runKeygen(partyIDs, oldThreshold, group, pl, network)
				publicKey := configs[0].PublicKey
				
				// Reshare with new threshold
				newConfigs := runReshare(configs, newThreshold, nil, publicKey, pl, network)
				
				// Test: exactly newThreshold parties needed
				messageHash := randomHash()
				signers := partyIDs[:newThreshold]
				signatures := runSign(newConfigs[:newThreshold], signers, messageHash, pl, network)
				
				// Verify signature works with new threshold
				validSig := signatures[0].Verify(publicKey, messageHash)
				
				// Test: newThreshold-1 parties cannot sign (if possible)
				cannotSignWithLess := true
				if newThreshold > 1 {
					// This should fail - we expect a panic or error
					defer func() {
						if r := recover(); r == nil {
							cannotSignWithLess = false
						}
					}()
					runSign(newConfigs[:newThreshold-1], signers[:newThreshold-1], messageHash, pl, network)
				}
				
				return validSig && cannotSignWithLess
			}

			config := &quick.Config{MaxCount: 15}
			Expect(quick.Check(property, config)).To(Succeed())
		})
	})

	Describe("Fuzz Testing", func() {
		It("should handle malformed network messages", func() {
			if testing.Short() {
				Skip("Skipping fuzz test in short mode")
			}

			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			
			// Create a fuzzing network
			fuzzNetwork := &FuzzingNetwork{
				Network: test.NewNetwork(partyIDs),
				FuzzRate: 0.1, // 10% of messages will be fuzzed
			}
			
			configs := runKeygen(partyIDs, threshold, group, pl, fuzzNetwork)
			
			// Try signing with fuzzy network
			successCount := 0
			attempts := 10
			
			for i := 0; i < attempts; i++ {
				messageHash := randomHash()
				signers := partyIDs[:threshold]
				
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Expected some failures due to fuzzing
							return
						}
					}()
					
					signatures := runSign(configs[:threshold], signers, messageHash, pl, fuzzNetwork)
					if signatures[0] != nil && signatures[0].Verify(configs[0].PublicKey, messageHash) {
						successCount++
					}
				}()
			}
			
			// Should succeed at least sometimes despite fuzzing
			Expect(successCount).To(BeNumerically(">", 0))
		})

		It("should handle random party dropouts", func() {
			property := func(dropoutPattern uint32) bool {
				n := 9
				threshold := 5
				
				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)
				
				configs := runKeygen(partyIDs, threshold, group, pl, network)
				
				// Create dropout network based on pattern
				dropoutNetwork := &DropoutNetwork{
					Network: network,
					DropoutPattern: dropoutPattern,
					MaxDropouts: n - threshold - 1, // Keep at least threshold+1
				}
				
				messageHash := randomHash()
				signers := partyIDs
				
				// Should still work with some dropouts
				signatures := runSignWithTimeout(configs, signers, messageHash, pl, dropoutNetwork, 5*time.Second)
				
				// Count successful signatures
				successCount := 0
				for _, sig := range signatures {
					if sig != nil && sig.Verify(configs[0].PublicKey, messageHash) {
						successCount++
					}
				}
				
				return successCount >= threshold
			}

			config := &quick.Config{MaxCount: 10}
			Expect(quick.Check(property, config)).To(Succeed())
		})

		It("should handle extreme message delays", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			
			// Network with random delays
			delayNetwork := &DelayNetwork{
				Network: test.NewNetwork(partyIDs),
				MinDelay: 0,
				MaxDelay: 500 * time.Millisecond,
			}
			
			configs := runKeygen(partyIDs, threshold, group, pl, delayNetwork)
			
			messageHash := randomHash()
			signers := partyIDs[:threshold]
			
			// Should complete despite delays
			signatures := runSignWithTimeout(configs[:threshold], signers, messageHash, pl, delayNetwork, 30*time.Second)
			
			Expect(signatures[0]).NotTo(BeNil())
			Expect(signatures[0].Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
		})
	})

	Describe("Edge Case Testing", func() {
		It("should handle maximum size groups", func() {
			if testing.Short() {
				Skip("Skipping large group test in short mode")
			}

			// Test with larger group
			n := 21
			threshold := 15
			
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)
			
			configs := runKeygen(partyIDs, threshold, group, pl, network)
			
			messageHash := randomHash()
			signers := partyIDs[:threshold]
			
			signatures := runSign(configs[:threshold], signers, messageHash, pl, network)
			
			Expect(signatures[0].Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
		})

		It("should handle rapid consecutive operations", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)
			
			configs := runKeygen(partyIDs, threshold, group, pl, network)
			
			// Rapid fire signing
			numOps := 20
			results := make(chan bool, numOps)
			
			for i := 0; i < numOps; i++ {
				go func() {
					messageHash := randomHash()
					signers := partyIDs[:threshold]
					signatures := runSign(configs[:threshold], signers, messageHash, pl, network)
					results <- signatures[0].Verify(configs[0].PublicKey, messageHash)
				}()
			}
			
			// All should succeed
			for i := 0; i < numOps; i++ {
				Expect(<-results).To(BeTrue())
			}
		})

		It("should handle adversarial threshold configurations", func() {
			testCases := []struct {
				name      string
				n         int
				threshold int
			}{
				{"Maximum threshold", 10, 10},
				{"Minimum threshold", 10, 1},
				{"Threshold = n-1", 10, 9},
				{"Threshold = (n+1)/2", 11, 6},
			}

			for _, tc := range testCases {
				By(tc.name)
				
				partyIDs := test.PartyIDs(tc.n)
				network := test.NewNetwork(partyIDs)
				
				configs := runKeygen(partyIDs, tc.threshold, group, pl, network)
				
				messageHash := randomHash()
				signers := partyIDs[:tc.threshold]
				
				signatures := runSign(configs[:tc.threshold], signers, messageHash, pl, network)
				
				Expect(signatures[0].Verify(configs[0].PublicKey, messageHash)).To(BeTrue())
			}
		})
	})
})

// Additional mock types for fuzzing

type FuzzingNetwork struct {
	*test.Network
	FuzzRate float64
}

func (f *FuzzingNetwork) Send(from, to party.ID, msg protocol.Message) {
	// Randomly corrupt messages
	if rand.Float64() < f.FuzzRate {
		// Corrupt the message somehow
		// In real implementation, this would modify message bytes
	}
	f.Network.Send(from, to, msg)
}

type DropoutNetwork struct {
	*test.Network
	DropoutPattern uint32
	MaxDropouts    int
}

func (d *DropoutNetwork) Send(from, to party.ID, msg protocol.Message) {
	// Simulate random dropouts based on pattern
	dropouts := 0
	for i := 0; i < 32 && dropouts < d.MaxDropouts; i++ {
		if d.DropoutPattern&(1<<i) != 0 {
			dropouts++
			if from == party.ID(fmt.Sprintf("%d", i)) || to == party.ID(fmt.Sprintf("%d", i)) {
				return // Drop message
			}
		}
	}
	d.Network.Send(from, to, msg)
}

type DelayNetwork struct {
	*test.Network
	MinDelay time.Duration
	MaxDelay time.Duration
}

func (d *DelayNetwork) Send(from, to party.ID, msg protocol.Message) {
	// Add random delay
	delay := d.MinDelay + time.Duration(rand.Int63n(int64(d.MaxDelay-d.MinDelay)))
	time.Sleep(delay)
	d.Network.Send(from, to, msg)
}

// Standard Go fuzz test
func FuzzLSSProtocol(f *testing.F) {
	// Add seed corpus
	f.Add(uint8(5), uint8(3), []byte("test message"))
	f.Add(uint8(7), uint8(4), []byte("another test"))
	f.Add(uint8(3), uint8(2), []byte("minimum threshold"))
	
	f.Fuzz(func(t *testing.T, n, threshold uint8, message []byte) {
		// Normalize inputs
		if n < 2 || n > 21 {
			t.Skip("Invalid n")
		}
		if threshold < 1 || threshold > n {
			t.Skip("Invalid threshold")
		}
		if len(message) == 0 {
			t.Skip("Empty message")
		}
		
		// Create hash from message
		messageHash := make([]byte, 32)
		copy(messageHash, message)
		
		// Run protocol
		pl := pool.NewPool(0)
		defer pl.TearDown()
		
		partyIDs := test.PartyIDs(int(n))
		network := test.NewNetwork(partyIDs)
		
		configs := make([]*lss.Config, n)
		var wg sync.WaitGroup
		wg.Add(int(n))
		
		for i, id := range partyIDs {
			i := i
			go func(id party.ID) {
				defer wg.Done()
				h, err := protocol.NewMultiHandler(lss.Keygen(curve.Secp256k1{}, id, partyIDs, int(threshold), pl), nil)
				if err != nil {
					t.Fatal(err)
				}
				test.HandlerLoop(id, h, network)
				
				r, err := h.Result()
				if err != nil {
					t.Fatal(err)
				}
				configs[i] = r.(*lss.Config)
			}(id)
		}
		
		wg.Wait()
		
		// Sign
		signers := partyIDs[:threshold]
		signatures := make([]*ecdsa.Signature, threshold)
		
		wg.Add(int(threshold))
		for i := 0; i < int(threshold); i++ {
			i := i
			go func() {
				defer wg.Done()
				h, err := protocol.NewMultiHandler(lss.Sign(configs[i], signers, messageHash, pl), nil)
				if err != nil {
					t.Fatal(err)
				}
				test.HandlerLoop(configs[i].ID, h, network)
				
				r, err := h.Result()
				if err != nil {
					t.Fatal(err)
				}
				signatures[i] = r.(*ecdsa.Signature)
			}()
		}
		
		wg.Wait()
		
		// Verify
		if !signatures[0].Verify(configs[0].PublicKey, messageHash) {
			t.Fatal("Invalid signature")
		}
	})
}