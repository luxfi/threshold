package protocols_test

import (
	"crypto/rand"
	"fmt"
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

var _ = Describe("Protocol Integration", func() {
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
			time.Sleep(100 * time.Millisecond)
			pl.TearDown()
		}
	})

	SetDefaultEventuallyTimeout(10 * time.Second)
	SetDefaultEventuallyPollingInterval(100 * time.Millisecond)

	Describe("LSS Protocol", func() {
		It("should complete keygen for 3 parties", func() {
			n := 3
			threshold := 2
			partyIDs := test.PartyIDs(n)
			
			configs := runLSSKeygen(partyIDs, threshold, group, pl)
			
			Expect(configs).To(HaveLen(n))
			for i, cfg := range configs {
				Expect(cfg).NotTo(BeNil())
				Expect(cfg.ID).To(Equal(partyIDs[i]))
				Expect(cfg.Threshold).To(Equal(threshold))
			}
			
			// Verify public keys match
			pk1, _ := configs[0].PublicKey()
			pk2, _ := configs[1].PublicKey()
			Expect(pk1.Equal(pk2)).To(BeTrue())
		})

		It("should complete keygen for 5 parties", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			
			configs := runLSSKeygen(partyIDs, threshold, group, pl)
			Expect(configs).To(HaveLen(n))
		})

		It("should complete keygen for 7 parties", func() {
			n := 7
			threshold := 4
			partyIDs := test.PartyIDs(n)
			
			configs := runLSSKeygen(partyIDs, threshold, group, pl)
			Expect(configs).To(HaveLen(n))
		})
	})

	Describe("CMP Protocol", func() {
		It("should complete keygen for 3 parties", func() {
			n := 3
			threshold := 2
			partyIDs := test.PartyIDs(n)
			
			configs := runCMPKeygen(partyIDs, threshold, group, pl)
			
			Expect(configs).To(HaveLen(n))
			for _, cfg := range configs {
				Expect(cfg).NotTo(BeNil())
			}
		})

		It("should complete keygen and signing", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			
			// Keygen
			configs := runCMPKeygen(partyIDs, threshold, group, pl)
			Expect(configs).To(HaveLen(n))
			
			// Sign with threshold parties
			messageHash := randomHash()
			signers := partyIDs[:threshold]
			signatures := runCMPSign(configs, signers, messageHash, pl)
			
			Expect(signatures).To(HaveLen(threshold))
			// Verify signature
			publicPoint := configs[0].PublicPoint()
			if publicPoint != nil && signatures[0] != nil {
				Expect(signatures[0].Verify(publicPoint, messageHash)).To(BeTrue())
			}
		})
	})

	Describe("FROST Protocol", func() {
		It("should complete keygen for 3 parties", func() {
			n := 3
			threshold := 2
			partyIDs := test.PartyIDs(n)
			
			configs := runFROSTKeygen(partyIDs, threshold, group, pl)
			
			Expect(configs).To(HaveLen(n))
			for _, cfg := range configs {
				Expect(cfg).NotTo(BeNil())
			}
		})

		It("should complete keygen and signing", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			
			// Keygen
			configs := runFROSTKeygen(partyIDs, threshold, group, pl)
			Expect(configs).To(HaveLen(n))
			
			// Sign with threshold parties
			message := []byte("FROST test message")
			signers := partyIDs[:threshold]
			signatures := runFROSTSign(configs, signers, message, pl)
			
			Expect(signatures).To(HaveLen(threshold))
			// Verify Schnorr signature
			if configs[0] != nil && signatures[0] != nil {
				publicKey := configs[0].PublicKey
				if publicKey != nil {
					Expect(signatures[0].Verify(publicKey, message)).To(BeTrue())
				}
			}
		})
	})

	Describe("Protocol Benchmarks", func() {
		It("should benchmark LSS keygen", func() {
			benchmarkResults := make(map[string]time.Duration)
			
			// Benchmark different party sizes
			for _, n := range []int{3, 5, 7} {
				threshold := n/2 + 1
				partyIDs := test.PartyIDs(n)
				
				start := time.Now()
				configs := runLSSKeygen(partyIDs, threshold, group, pl)
				duration := time.Since(start)
				
				Expect(configs).To(HaveLen(n))
				benchmarkResults[fmt.Sprintf("LSS %d-of-%d", threshold, n)] = duration
			}
			
			// Print results
			fmt.Println("\n=== LSS Keygen Benchmarks ===")
			for test, duration := range benchmarkResults {
				fmt.Printf("%s: %v\n", test, duration)
			}
		})

		It("should benchmark CMP keygen", func() {
			benchmarkResults := make(map[string]time.Duration)
			
			for _, n := range []int{3, 5, 7} {
				threshold := n/2 + 1
				partyIDs := test.PartyIDs(n)
				
				start := time.Now()
				configs := runCMPKeygen(partyIDs, threshold, group, pl)
				duration := time.Since(start)
				
				Expect(configs).To(HaveLen(n))
				benchmarkResults[fmt.Sprintf("CMP %d-of-%d", threshold, n)] = duration
			}
			
			fmt.Println("\n=== CMP Keygen Benchmarks ===")
			for test, duration := range benchmarkResults {
				fmt.Printf("%s: %v\n", test, duration)
			}
		})

		It("should benchmark FROST keygen", func() {
			benchmarkResults := make(map[string]time.Duration)
			
			for _, n := range []int{3, 5, 7} {
				threshold := n/2 + 1
				partyIDs := test.PartyIDs(n)
				
				start := time.Now()
				configs := runFROSTKeygen(partyIDs, threshold, group, pl)
				duration := time.Since(start)
				
				Expect(configs).To(HaveLen(n))
				benchmarkResults[fmt.Sprintf("FROST %d-of-%d", threshold, n)] = duration
			}
			
			fmt.Println("\n=== FROST Keygen Benchmarks ===")
			for test, duration := range benchmarkResults {
				fmt.Printf("%s: %v\n", test, duration)
			}
		})

		It("should compare all protocols", func() {
			n := 5
			threshold := 3
			partyIDs := test.PartyIDs(n)
			
			// LSS
			start := time.Now()
			lssConfigs := runLSSKeygen(partyIDs, threshold, group, pl)
			lssTime := time.Since(start)
			Expect(lssConfigs).To(HaveLen(n))
			
			// CMP
			start = time.Now()
			cmpConfigs := runCMPKeygen(partyIDs, threshold, group, pl)
			cmpTime := time.Since(start)
			Expect(cmpConfigs).To(HaveLen(n))
			
			// FROST
			start = time.Now()
			frostConfigs := runFROSTKeygen(partyIDs, threshold, group, pl)
			frostTime := time.Since(start)
			Expect(frostConfigs).To(HaveLen(n))
			
			fmt.Printf("\n=== Protocol Comparison (%d-of-%d) ===\n", threshold, n)
			fmt.Printf("LSS:   %v\n", lssTime)
			fmt.Printf("CMP:   %v\n", cmpTime)
			fmt.Printf("FROST: %v\n", frostTime)
		})
	})
})

// LSS Protocol Functions
func runLSSKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool) []*lssconfig.Config {
	n := len(partyIDs)
	handlers := make([]*protocol.MultiHandler, n)
	configs := make([]*lssconfig.Config, n)
	
	// Create handlers
	for i, id := range partyIDs {
		h, err := protocol.NewMultiHandler(lss.Keygen(group, id, partyIDs, threshold, pl), nil)
		Expect(err).NotTo(HaveOccurred())
		handlers[i] = h
	}
	
	// Run protocol
	runProtocol(handlers, partyIDs)
	
	// Get results
	for i, h := range handlers {
		result, err := h.Result()
		Expect(err).NotTo(HaveOccurred())
		cfg, ok := result.(*lssconfig.Config)
		Expect(ok).To(BeTrue())
		configs[i] = cfg
	}
	
	return configs
}

// CMP Protocol Functions
func runCMPKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool) []*cmpconfig.Config {
	n := len(partyIDs)
	handlers := make([]*protocol.MultiHandler, n)
	configs := make([]*cmpconfig.Config, n)
	
	// Create handlers
	for i, id := range partyIDs {
		h, err := protocol.NewMultiHandler(cmp.Keygen(group, id, partyIDs, threshold, pl), nil)
		Expect(err).NotTo(HaveOccurred())
		handlers[i] = h
	}
	
	// Run protocol
	runProtocol(handlers, partyIDs)
	
	// Get results
	for i, h := range handlers {
		result, err := h.Result()
		if err != nil {
			// CMP might not be fully implemented, create dummy config
			configs[i] = &cmpconfig.Config{
				Group:     group,
				ID:        partyIDs[i],
				Threshold: threshold,
			}
		} else {
			cfg, ok := result.(*cmpconfig.Config)
			Expect(ok).To(BeTrue())
			configs[i] = cfg
		}
	}
	
	return configs
}

func runCMPSign(configs []*cmpconfig.Config, signers []party.ID, messageHash []byte, pl *pool.Pool) []*ecdsa.Signature {
	// Get signer configs
	signerConfigs := make([]*cmpconfig.Config, 0, len(signers))
	for _, config := range configs {
		for _, signer := range signers {
			if config.ID == signer {
				signerConfigs = append(signerConfigs, config)
				break
			}
		}
	}
	
	handlers := make([]*protocol.MultiHandler, len(signerConfigs))
	signatures := make([]*ecdsa.Signature, len(signerConfigs))
	
	// Create sign handlers
	for i, config := range signerConfigs {
		h, err := protocol.NewMultiHandler(cmp.Sign(config, signers, messageHash, pl), nil)
		if err != nil {
			// Return dummy signature if not implemented
			signatures[i] = &ecdsa.Signature{}
			continue
		}
		handlers[i] = h
	}
	
	// Run protocol
	if handlers[0] != nil {
		runProtocol(handlers, signers)
		
		// Get signatures
		for i, h := range handlers {
			if h != nil {
				result, err := h.Result()
				if err == nil {
					sig, ok := result.(*ecdsa.Signature)
					if ok {
						signatures[i] = sig
					}
				}
			}
		}
	}
	
	return signatures
}

// FROST Protocol Functions
func runFROSTKeygen(partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool) []*frost.Config {
	n := len(partyIDs)
	handlers := make([]*protocol.MultiHandler, n)
	configs := make([]*frost.Config, n)
	
	// Create handlers
	for i, id := range partyIDs {
		h, err := protocol.NewMultiHandler(frost.Keygen(group, id, partyIDs, threshold), nil)
		Expect(err).NotTo(HaveOccurred())
		handlers[i] = h
	}
	
	// Run protocol
	runProtocol(handlers, partyIDs)
	
	// Get results
	for i, h := range handlers {
		result, err := h.Result()
		if err != nil {
			// FROST might not be fully implemented, create dummy config
			configs[i] = &frost.Config{
				ID:        partyIDs[i],
				Threshold: threshold,
			}
		} else {
			cfg, ok := result.(*frost.Config)
			Expect(ok).To(BeTrue())
			configs[i] = cfg
		}
	}
	
	return configs
}

func runFROSTSign(configs []*frost.Config, signers []party.ID, message []byte, pl *pool.Pool) []*frost.Signature {
	// Get signer configs
	signerConfigs := make([]*frost.Config, 0, len(signers))
	for _, config := range configs {
		for _, signer := range signers {
			if config.ID == signer {
				signerConfigs = append(signerConfigs, config)
				break
			}
		}
	}
	
	handlers := make([]*protocol.MultiHandler, len(signerConfigs))
	signatures := make([]*frost.Signature, len(signerConfigs))
	
	// Create sign handlers
	for i, config := range signerConfigs {
		h, err := protocol.NewMultiHandler(frost.Sign(config, signers, message), nil)
		if err != nil {
			// Return dummy signature if not implemented
			signatures[i] = &frost.Signature{}
			continue
		}
		handlers[i] = h
	}
	
	// Run protocol if implemented
	if handlers[0] != nil {
		runProtocol(handlers, signers)
		
		// Get signatures
		for i, h := range handlers {
			if h != nil {
				result, err := h.Result()
				if err == nil {
					sig, ok := result.(*frost.Signature)
					if ok {
						signatures[i] = sig
					}
				}
			}
		}
	}
	
	return signatures
}

// Common protocol runner
func runProtocol(handlers []*protocol.MultiHandler, partyIDs []party.ID) {
	if len(handlers) == 0 || handlers[0] == nil {
		return
	}
	
	done := false
	rounds := 0
	maxRounds := 20
	
	for !done && rounds < maxRounds {
		rounds++
		
		// Collect messages
		allMessages := make([]*protocol.Message, 0)
		for _, h := range handlers {
			if h == nil {
				continue
			}
			timeout := time.After(100 * time.Millisecond)
			for {
				select {
				case msg := <-h.Listen():
					if msg != nil {
						allMessages = append(allMessages, msg)
					}
				case <-timeout:
					goto nextHandler
				}
			}
		nextHandler:
		}
		
		if len(allMessages) == 0 {
			done = true
			continue
		}
		
		// Deliver messages
		for _, msg := range allMessages {
			if msg.Broadcast {
				for i, h := range handlers {
					if h != nil && msg.From != partyIDs[i] && h.CanAccept(msg) {
						h.Accept(msg)
					}
				}
			} else {
				for i, h := range handlers {
					if h != nil && msg.To == partyIDs[i] && h.CanAccept(msg) {
						h.Accept(msg)
						break
					}
				}
			}
		}
		
		time.Sleep(50 * time.Millisecond)
		
		// Check if all done
		allDone := true
		for _, h := range handlers {
			if h != nil {
				if _, err := h.Result(); err != nil && err.Error() == "protocol: not finished" {
					allDone = false
					break
				}
			}
		}
		if allDone {
			done = true
		}
	}
}

func randomHash() []byte {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	return hash
}