package lss

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
)

// BenchmarkLSSKeygen benchmarks the key generation protocol
func BenchmarkLSSKeygen(b *testing.B) {
	benchmarks := []struct {
		name      string
		n         int
		threshold int
	}{
		{"3-of-5", 5, 3},
		{"5-of-9", 9, 5},
		{"7-of-11", 11, 7},
		{"10-of-15", 15, 10},
		{"15-of-21", 21, 15},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				pl := pool.NewPool(0)
				partyIDs := test.PartyIDs(bm.n)
				network := test.NewNetwork(partyIDs)
				b.StartTimer()

				var wg sync.WaitGroup
				wg.Add(bm.n)

				for _, id := range partyIDs {
					go func(id party.ID) {
						defer wg.Done()
						h, _ := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, partyIDs, bm.threshold, pl), nil)
						test.HandlerLoop(id, h, network)
					}(id)
				}

				wg.Wait()
				b.StopTimer()
				pl.TearDown()
			}
		})
	}
}

// BenchmarkLSSSign benchmarks the signing protocol
func BenchmarkLSSSign(b *testing.B) {
	benchmarks := []struct {
		name      string
		n         int
		threshold int
		signers   int
	}{
		{"3-signers-of-5", 5, 3, 3},
		{"5-signers-of-9", 9, 5, 5},
		{"7-signers-of-11", 11, 7, 7},
		{"all-5-signers", 5, 3, 5},
		{"all-9-signers", 9, 5, 9},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Setup
			pl := pool.NewPool(0)
			defer pl.TearDown()
			partyIDs := test.PartyIDs(bm.n)
			network := test.NewNetwork(partyIDs)

			// Run keygen once
			configs := runKeygenBench(b, partyIDs, bm.threshold, curve.Secp256k1{}, pl, network)
			signers := partyIDs[:bm.signers]

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				messageHash := make([]byte, 32)
				_, err := rand.Read(messageHash)
				if err != nil {
					b.Fatal(err)
				}

				var wg sync.WaitGroup
				wg.Add(bm.signers)

				for j := 0; j < bm.signers; j++ {
					go func(idx int) {
						defer wg.Done()
						h, _ := protocol.NewMultiHandler(Sign(configs[idx], signers, messageHash, pl), nil)
						test.HandlerLoop(configs[idx].ID, h, network)
					}(j)
				}

				wg.Wait()
			}
		})
	}
}

// BenchmarkLSSReshare benchmarks the resharing protocol
func BenchmarkLSSReshare(b *testing.B) {
	benchmarks := []struct {
		name          string
		initialN      int
		threshold     int
		newThreshold  int
		addParties    int
		removeParties int
	}{
		{"5to7-parties", 5, 3, 3, 2, 0},
		{"7to5-parties", 7, 4, 3, 0, 2},
		{"5to5-threshold-change", 5, 3, 4, 0, 0},
		{"9to11-parties", 9, 5, 6, 2, 0},
		{"rotate-3-of-5", 5, 3, 3, 1, 1},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Setup
			pl := pool.NewPool(0)
			defer pl.TearDown()
			initialPartyIDs := test.PartyIDs(bm.initialN)
			network := test.NewNetwork(initialPartyIDs)

			// Run initial keygen
			configs := runKeygenBench(b, initialPartyIDs, bm.threshold, curve.Secp256k1{}, pl, network)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Prepare new party set
				newParties := test.PartyIDs(bm.addParties)
				remainingConfigs := configs[:len(configs)-bm.removeParties]
				
				allParties := append(remainingConfigs[0].PartyIDs, newParties...)
				reshareNetwork := test.NewNetwork(allParties)
				b.StartTimer()

				var wg sync.WaitGroup
				wg.Add(len(remainingConfigs) + len(newParties))

				// Existing parties reshare
				for _, config := range remainingConfigs {
					go func(c *Config) {
						defer wg.Done()
						h, _ := protocol.NewMultiHandler(Reshare(c, bm.newThreshold, newParties, pl), nil)
						test.HandlerLoop(c.ID, h, reshareNetwork)
					}(config)
				}

				// New parties join
				for _, newID := range newParties {
					go func(id party.ID) {
						defer wg.Done()
						emptyConfig := &Config{
							ID:           id,
							Group:        curve.Secp256k1{},
							PublicKey:    configs[0].PublicKey,
							Generation:   configs[0].Generation,
							PartyIDs:     remainingConfigs[0].PartyIDs,
							PublicShares: make(map[party.ID]curve.Point),
						}
						h, _ := protocol.NewMultiHandler(Reshare(emptyConfig, bm.newThreshold, newParties, pl), nil)
						test.HandlerLoop(id, h, reshareNetwork)
					}(newID)
				}

				wg.Wait()
			}
		})
	}
}

// BenchmarkLSSSignWithBlinding benchmarks blinded signing protocols
func BenchmarkLSSSignWithBlinding(b *testing.B) {
	protocols := []struct {
		name     string
		protocol int
	}{
		{"Protocol-I", 1},
		{"Protocol-II", 2},
	}

	n := 5
	threshold := 3

	for _, p := range protocols {
		b.Run(p.name, func(b *testing.B) {
			// Setup
			pl := pool.NewPool(0)
			defer pl.TearDown()
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			configs := runKeygenBench(b, partyIDs, threshold, curve.Secp256k1{}, pl, network)
			signers := partyIDs[:threshold]

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				messageHash := make([]byte, 32)
				_, err := rand.Read(messageHash)
				if err != nil {
					b.Fatal(err)
				}

				var wg sync.WaitGroup
				wg.Add(threshold)

				for j := 0; j < threshold; j++ {
					go func(idx int) {
						defer wg.Done()
						h, _ := protocol.NewMultiHandler(SignWithBlinding(configs[idx], signers, messageHash, p.protocol, pl), nil)
						test.HandlerLoop(configs[idx].ID, h, network)
					}(j)
				}

				wg.Wait()
			}
		})
	}
}

// BenchmarkLSSParallelSigning benchmarks parallel signing operations
func BenchmarkLSSParallelSigning(b *testing.B) {
	parallelOps := []int{1, 2, 4, 8, 16}
	n := 7
	threshold := 4

	for _, ops := range parallelOps {
		b.Run(fmt.Sprintf("parallel-%d", ops), func(b *testing.B) {
			// Setup
			pl := pool.NewPool(0)
			defer pl.TearDown()
			partyIDs := test.PartyIDs(n)
			network := test.NewNetwork(partyIDs)

			configs := runKeygenBench(b, partyIDs, threshold, curve.Secp256k1{}, pl, network)
			signers := partyIDs[:threshold]

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var opWg sync.WaitGroup
				opWg.Add(ops)

				for op := 0; op < ops; op++ {
					go func() {
						defer opWg.Done()
						messageHash := make([]byte, 32)
						_, err := rand.Read(messageHash)
						if err != nil {
							b.Fatal(err)
						}

						var wg sync.WaitGroup
						wg.Add(threshold)

						for j := 0; j < threshold; j++ {
							go func(idx int) {
								defer wg.Done()
								h, _ := protocol.NewMultiHandler(Sign(configs[idx], signers, messageHash, pl), nil)
								test.HandlerLoop(configs[idx].ID, h, network)
							}(j)
						}

						wg.Wait()
					}()
				}

				opWg.Wait()
			}
		})
	}
}

// Helper for benchmarks - same as in test but returns testing.TB
func runKeygenBench(tb testing.TB, partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool, network *test.Network) []*Config {
	var wg sync.WaitGroup
	wg.Add(len(partyIDs))

	configs := make([]*Config, len(partyIDs))
	for i, id := range partyIDs {
		i := i
		go func(id party.ID) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(Keygen(group, id, partyIDs, threshold, pl), nil)
			if err != nil {
				tb.Fatal(err)
			}
			test.HandlerLoop(id, h, network)
			
			r, err := h.Result()
			if err != nil {
				tb.Fatal(err)
			}
			configs[i] = r.(*Config)
		}(id)
	}

	wg.Wait()
	return configs
}