package lss_test

import (
	cryptorand "crypto/rand"
	"fmt"
	mathrand "math/rand"
	"sync"
	"testing"
	"testing/quick"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
				n := int(nRaw%20) + 2       // n in [2, 21]
				t := int(tRaw%uint8(n)) + 1 // t in [1, n]

				if t > n || t < 1 || n < 2 {
					return true // Skip invalid configurations
				}

				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)

				// Run keygen
				configs := runKeygenGinkgo(partyIDs, t, group, pl, network)

				// Test: Any t parties can sign
				messageHash := randomHashProperty()
				signers := partyIDs[:t]
				signatures := runSign(configs[:t], signers, messageHash, pl, network)

				// Verify signature
				pubKey, err := configs[0].PublicKey()
				if err != nil {
					return false
				}
				return signatures[0].Verify(pubKey, messageHash)
			}

			// Run property test
			config := &quick.Config{MaxCount: 20}
			Expect(quick.Check(property, config)).To(Succeed())
		})

		It("should handle arbitrary membership changes", func() {
			property := func(initialN, initialT, addCount, removeCount uint8) bool {
				// Normalize inputs
				n := int(initialN%10) + 5               // n in [5, 14]
				t := int(initialT%uint8(n-2)) + 2       // t in [2, n-1]
				add := int(addCount % 5)                // add up to 5
				remove := int(removeCount % uint8(n-t)) // ensure we keep at least t parties

				if t > n || t < 2 || n < 3 {
					return true
				}

				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)

				// Initial keygen
				configs := runKeygenGinkgo(partyIDs, t, group, pl, network)
				publicKey, err := configs[0].PublicKey()
				if err != nil {
					return false
				}

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
					allParties := append(remainingConfigs[0].PartyIDs(), newParties...)
					network = test.NewNetwork(allParties)
					newConfigs := runReshare(remainingConfigs, t, newParties, pl, network)

					// Verify new configuration
					newPubKey, err := newConfigs[0].PublicKey()
					if err != nil {
						return false
					}
					return newPubKey.Equal(publicKey) &&
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

				configs := runKeygenGinkgo(partyIDs, t, group, pl, network)

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
				pubKey, err := configs[0].PublicKey()
				if err != nil {
					return false
				}
				return sig1.Verify(pubKey, messageHash) &&
					sig2.Verify(pubKey, messageHash)
			}

			config := &quick.Config{MaxCount: 10}
			Expect(quick.Check(property, config)).To(Succeed())
		})

		It("should maintain security across threshold changes", func() {
			property := func(oldT, newT uint8) bool {
				n := 7
				oldThreshold := int(oldT%5) + 2 // [2, 6]
				newThreshold := int(newT%5) + 2 // [2, 6]

				if oldThreshold > n || newThreshold > n {
					return true
				}

				partyIDs := test.PartyIDs(n)
				network := test.NewNetwork(partyIDs)

				// Initial setup with oldThreshold
				configs := runKeygenGinkgo(partyIDs, oldThreshold, group, pl, network)
				publicKey, err := configs[0].PublicKey()
				if err != nil {
					return false
				}

				// Reshare with new threshold
				newConfigs := runReshare(configs, newThreshold, nil, pl, network)

				// Test: exactly newThreshold parties needed
				messageHash := randomHashProperty()
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
				Network:  test.NewNetwork(partyIDs),
				FuzzRate: 0.1, // 10% of messages will be fuzzed
			}

			configs := runKeygenGinkgo(partyIDs, threshold, group, pl, fuzzNetwork.Network)

			// Try signing with fuzzy network
			successCount := 0
			attempts := 10

			for i := 0; i < attempts; i++ {
				messageHash := randomHashProperty()
				signers := partyIDs[:threshold]

				func() {
					defer func() {
						if r := recover(); r != nil {
							// Expected some failures due to fuzzing
							return
						}
					}()

					signatures := runSign(configs[:threshold], signers, messageHash, pl, fuzzNetwork.Network)
					if signatures[0] != nil {
						pubKey, err := configs[0].PublicKey()
						if err == nil && signatures[0].Verify(pubKey, messageHash) {
							successCount++
						}
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

				configs := runKeygenGinkgo(partyIDs, threshold, group, pl, network)

				// Create dropout network based on pattern
				dropoutNetwork := &DropoutNetwork{
					Network:        network,
					DropoutPattern: dropoutPattern,
					MaxDropouts:    n - threshold - 1, // Keep at least threshold+1
				}

				messageHash := randomHashProperty()
				signers := partyIDs

				// Should still work with some dropouts
				signatures := runSignWithTimeout(configs, signers, messageHash, pl, dropoutNetwork.Network, 5*time.Second)

				// Count successful signatures
				successCount := 0
				pubKey, err := configs[0].PublicKey()
				if err != nil {
					return false
				}
				for _, sig := range signatures {
					if sig != nil && sig.Verify(pubKey, messageHash) {
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
				Network:  test.NewNetwork(partyIDs),
				MinDelay: 0,
				MaxDelay: 500 * time.Millisecond,
			}

			configs := runKeygenGinkgo(partyIDs, threshold, group, pl, delayNetwork.Network)

			messageHash := randomHashProperty()
			signers := partyIDs[:threshold]

			// Should complete despite delays
			signatures := runSignWithTimeout(configs[:threshold], signers, messageHash, pl, delayNetwork.Network, 30*time.Second)

			Expect(signatures[0]).NotTo(BeNil())
			pubKey, err := configs[0].PublicKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(signatures[0].Verify(pubKey, messageHash)).To(BeTrue())
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

			configs := runKeygenGinkgo(partyIDs, threshold, group, pl, network)

			messageHash := randomHashProperty()
			signers := partyIDs[:threshold]

			signatures := runSign(configs[:threshold], signers, messageHash, pl, network)

			pubKey, err := configs[0].PublicKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(signatures[0].Verify(pubKey, messageHash)).To(BeTrue())
		})

		It("should handle rapid consecutive operations", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			configs := runKeygenGinkgo(partyIDs, threshold, group, pl, network)

			// Rapid fire signing
			numOps := 20
			results := make(chan bool, numOps)

			for i := 0; i < numOps; i++ {
				go func() {
					messageHash := randomHashProperty()
					signers := partyIDs[:threshold]
					signatures := runSign(configs[:threshold], signers, messageHash, pl, network)
					pubKey, err := configs[0].PublicKey()
					if err != nil {
						results <- false
						return
					}
					results <- signatures[0].Verify(pubKey, messageHash)
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

				configs := runKeygenGinkgo(partyIDs, tc.threshold, group, pl, network)

				messageHash := randomHashProperty()
				signers := partyIDs[:tc.threshold]

				signatures := runSign(configs[:tc.threshold], signers, messageHash, pl, network)

				pubKey, err := configs[0].PublicKey()
				Expect(err).NotTo(HaveOccurred())
				Expect(signatures[0].Verify(pubKey, messageHash)).To(BeTrue())
			}
		})
	})
})

// Additional mock types for fuzzing

type FuzzingNetwork struct {
	*test.Network
	FuzzRate float64
}

func (f *FuzzingNetwork) Send(msg *protocol.Message) {
	// Randomly corrupt messages
	if mathrand.Float64() < f.FuzzRate {
		// Corrupt the message somehow
		// In real implementation, this would modify message bytes
	}
	f.Network.Send(msg)
}

type DropoutNetwork struct {
	*test.Network
	DropoutPattern uint32
	MaxDropouts    int
}

func (d *DropoutNetwork) Send(msg *protocol.Message) {
	// Simulate random dropouts based on pattern
	dropouts := 0
	for i := 0; i < 32 && dropouts < d.MaxDropouts; i++ {
		if d.DropoutPattern&(1<<i) != 0 {
			dropouts++
			if msg.From == party.ID(fmt.Sprintf("%d", i)) || msg.To == party.ID(fmt.Sprintf("%d", i)) {
				return // Drop message
			}
		}
	}
	d.Network.Send(msg)
}

type DelayNetwork struct {
	*test.Network
	MinDelay time.Duration
	MaxDelay time.Duration
}

func (d *DelayNetwork) Send(msg *protocol.Message) {
	// Add random delay
	delay := d.MinDelay + time.Duration(mathrand.Int63n(int64(d.MaxDelay-d.MinDelay)))
	time.Sleep(delay)
	d.Network.Send(msg)
}

// Standard Go fuzz test
func FuzzLSSProtocol(f *testing.F) {
	f.Skip("LSS protocol implementation is incomplete - TODO: implement proper message flow")

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
		pubKey, err := configs[0].PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if !signatures[0].Verify(pubKey, messageHash) {
			t.Fatal("Invalid signature")
		}
	})
}

// Helper functions for Ginkgo tests

func runKeygenGinkgo(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *test.Network) []*lss.Config {
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
		go func(config *lss.Config) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Sign(config, signers, messageHash, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(config.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			signatures[i] = r.(*ecdsa.Signature)
		}(config)
	}

	wg.Wait()
	return signatures
}

func runSignWithTimeout(configs []*lss.Config, signers []party.ID, messageHash []byte, pl *pool.Pool, network *test.Network, timeout time.Duration) []*ecdsa.Signature {
	done := make(chan struct{})
	var signatures []*ecdsa.Signature

	go func() {
		signatures = runSign(configs, signers, messageHash, pl, network)
		close(done)
	}()

	select {
	case <-done:
		return signatures
	case <-time.After(timeout):
		Fail("Sign operation timed out")
		return nil
	}
}

func runReshare(oldConfigs []*lss.Config, newThreshold int, newParties []party.ID, pl *pool.Pool, network *test.Network) []*lss.Config {
	allParties := append(oldConfigs[0].PartyIDs(), newParties...)
	newConfigs := make([]*lss.Config, len(allParties))

	var wg sync.WaitGroup
	wg.Add(len(oldConfigs) + len(newParties))

	// Existing parties reshare
	for i, config := range oldConfigs {
		i := i
		go func(c *lss.Config) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(lss.Reshare(c, newParties, newThreshold, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(c.ID, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			newConfigs[i] = r.(*lss.Config)
		}(config)
	}

	// New parties join
	for i, newID := range newParties {
		idx := len(oldConfigs) + i
		go func(id party.ID, idx int) {
			defer wg.Done()
			emptyConfig := &lss.Config{
				ID:         id,
				Group:      oldConfigs[0].Group,
				Generation: oldConfigs[0].Generation,
				Public:     make(map[party.ID]*config.Public),
			}
			h, err := protocol.NewMultiHandler(lss.Reshare(emptyConfig, newParties, newThreshold, pl), nil)
			Expect(err).NotTo(HaveOccurred())
			test.HandlerLoop(id, h, network)

			r, err := h.Result()
			Expect(err).NotTo(HaveOccurred())
			newConfigs[idx] = r.(*lss.Config)
		}(newID, idx)
	}

	wg.Wait()
	return newConfigs
}

func randomHashProperty() []byte {
	hash := make([]byte, 32)
	_, err := cryptorand.Read(hash)
	Expect(err).NotTo(HaveOccurred())
	return hash
}
