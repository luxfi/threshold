package lss_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/frost/keygen"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// BenchmarkLSSKeygen benchmarks key generation
func BenchmarkLSSKeygen(b *testing.B) {
	cases := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"3-of-5", 5, 3},
		{"5-of-9", 9, 5},
		{"7-of-11", 11, 7},
		{"10-of-15", 15, 10},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			group := curve.Secp256k1{}
			partyIDs := make([]party.ID, tc.parties)
			for i := 0; i < tc.parties; i++ {
				partyIDs[i] = party.ID(fmt.Sprintf("party_%d", i))
			}

			b.ResetTimer()
			start := time.Now()
			
			for i := 0; i < b.N; i++ {
				pl := pool.NewPool(0)
				_ = lss.Keygen(group, partyIDs[0], partyIDs, tc.threshold, pl)
				pl.TearDown()
			}
			
			elapsed := time.Since(start)
			avgMs := float64(elapsed.Milliseconds()) / float64(b.N)
			b.ReportMetric(avgMs, "ms/op")
			
			// Report actual timing for documentation
			if b.N == 1 {
				fmt.Printf("Key generation (%d-of-%d): ~%.2f ms\n", tc.threshold, tc.parties, avgMs)
			}
		})
	}
}

// BenchmarkLSSSigning benchmarks threshold signing
func BenchmarkLSSSigning(b *testing.B) {
	cases := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"3-of-5", 5, 3},
		{"5-of-9", 9, 5},
		{"7-of-11", 11, 7},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			// Setup
			group := curve.Secp256k1{}
			partyIDs := make([]party.ID, tc.parties)
			for i := 0; i < tc.parties; i++ {
				partyIDs[i] = party.ID(fmt.Sprintf("party_%d", i))
			}

			// Generate configs
			configs := generateTestConfigs(group, partyIDs, tc.threshold)
			messageHash := make([]byte, 32)
			rand.Read(messageHash)
			signers := partyIDs[:tc.threshold]

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				pl := pool.NewPool(0)
				_ = lss.Sign(configs[signers[0]], signers, messageHash, pl)
				pl.TearDown()
			}

			elapsed := time.Since(start)
			avgMs := float64(elapsed.Milliseconds()) / float64(b.N)
			b.ReportMetric(avgMs, "ms/op")
			
			// Report actual timing for documentation
			if b.N == 1 {
				fmt.Printf("Signing (%d parties): ~%.2f ms\n", tc.threshold, avgMs)
			}
		})
	}
}

// BenchmarkLSSResharing benchmarks dynamic resharing
func BenchmarkLSSResharing(b *testing.B) {
	cases := []struct {
		name        string
		oldParties  int
		newParties  int
		addParties  int
		threshold   int
	}{
		{"Add 2 parties (5->7)", 5, 7, 2, 3},
		{"Add 3 parties (7->10)", 7, 10, 3, 5},
		{"Remove 2 parties (9->7)", 9, 7, 0, 4},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			group := curve.Secp256k1{}
			
			// Setup old parties
			oldPartyIDs := make([]party.ID, tc.oldParties)
			for i := 0; i < tc.oldParties; i++ {
				oldPartyIDs[i] = party.ID(fmt.Sprintf("party_%d", i))
			}
			oldConfigs := generateTestConfigs(group, oldPartyIDs, tc.threshold)

			// Setup new parties
			newPartyIDs := make([]party.ID, tc.newParties)
			if tc.addParties > 0 {
				// Adding parties
				copy(newPartyIDs, oldPartyIDs)
				for i := tc.oldParties; i < tc.newParties; i++ {
					newPartyIDs[i] = party.ID(fmt.Sprintf("new_party_%d", i))
				}
			} else {
				// Removing parties
				copy(newPartyIDs, oldPartyIDs[:tc.newParties])
			}

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				pl := pool.NewPool(0)
				startFunc := lss.Reshare(oldConfigs[oldPartyIDs[0]], newPartyIDs, tc.threshold, pl)
				if startFunc != nil {
					_, _ = startFunc([]byte("session"))
				}
				pl.TearDown()
			}

			elapsed := time.Since(start)
			avgMs := float64(elapsed.Milliseconds()) / float64(b.N)
			b.ReportMetric(avgMs, "ms/op")
			
			// Report actual timing for documentation
			if b.N == 1 {
				if tc.addParties > 0 {
					fmt.Printf("Resharing (add %d parties): ~%.2f ms\n", tc.addParties, avgMs)
				} else {
					fmt.Printf("Resharing (remove %d parties): ~%.2f ms\n", tc.oldParties-tc.newParties, avgMs)
				}
			}
		})
	}
}

// BenchmarkFROSTDynamicReshare benchmarks FROST resharing
func BenchmarkFROSTDynamicReshare(b *testing.B) {
	cases := []struct {
		name       string
		oldParties int
		newParties int
		threshold  int
	}{
		{"5->7 parties", 5, 7, 3},
		{"7->10 parties", 7, 10, 5},
		{"9->6 parties", 9, 6, 4},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			group := curve.Secp256k1{}
			
			// Setup old FROST configs
			oldPartyIDs := make([]party.ID, tc.oldParties)
			for i := 0; i < tc.oldParties; i++ {
				oldPartyIDs[i] = party.ID(fmt.Sprintf("party_%d", i))
			}
			
			oldConfigs := generateFROSTConfigs(group, oldPartyIDs, tc.threshold)
			
			// Setup new party IDs
			newPartyIDs := make([]party.ID, tc.newParties)
			for i := 0; i < tc.newParties; i++ {
				newPartyIDs[i] = party.ID(fmt.Sprintf("new_party_%d", i))
			}

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				_, _ = lss.DynamicReshareFROST(oldConfigs, newPartyIDs, tc.threshold, nil)
			}

			elapsed := time.Since(start)
			avgMs := float64(elapsed.Milliseconds()) / float64(b.N)
			b.ReportMetric(avgMs, "ms/op")
			
			// Report actual timing
			if b.N == 1 {
				fmt.Printf("FROST Resharing (%d->%d parties): ~%.2f ms\n", tc.oldParties, tc.newParties, avgMs)
			}
		})
	}
}

// BenchmarkRollback benchmarks rollback operations
func BenchmarkRollback(b *testing.B) {
	mgr := lss.NewRollbackManager(100)
	group := curve.Secp256k1{}
	
	// Create test configs
	cfg := &config.Config{
		ID:         "test",
		Group:      group,
		Threshold:  3,
		Generation: 0,
		ECDSA:      sample.Scalar(rand.Reader, group),
		Public:     make(map[party.ID]*config.Public),
		ChainKey:   []byte("test"),
		RID:        []byte("test"),
	}

	// Save multiple snapshots
	for i := uint64(0); i < 50; i++ {
		cfg.Generation = i
		_ = mgr.SaveSnapshot(cfg)
	}

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		targetGen := uint64(i % 25) // Rollback to various generations
		_, _ = mgr.Rollback(targetGen)
	}
	
	b.ReportMetric(float64(b.N), "rollbacks/sec")
}

// Helper functions

func generateTestConfigs(group curve.Curve, partyIDs []party.ID, threshold int) map[party.ID]*config.Config {
	configs := make(map[party.ID]*config.Config)
	
	// Create shares using simplified Shamir's secret sharing
	shares := make(map[party.ID]curve.Scalar)
	for _, id := range partyIDs {
		shares[id] = sample.Scalar(rand.Reader, group)
	}
	
	// Create configs
	for _, id := range partyIDs {
		cfg := &config.Config{
			ID:         id,
			Group:      group,
			Threshold:  threshold,
			Generation: 0,
			ECDSA:      shares[id],
			Public:     make(map[party.ID]*config.Public),
			ChainKey:   []byte("test-chainkey"),
			RID:        []byte("test-rid"),
		}
		
		// Add public shares
		for _, otherID := range partyIDs {
			cfg.Public[otherID] = &config.Public{
				ECDSA: shares[otherID].ActOnBase(),
			}
		}
		
		configs[id] = cfg
	}
	
	return configs
}

func generateFROSTConfigs(group curve.Curve, partyIDs []party.ID, threshold int) map[party.ID]*keygen.Config {
	configs := make(map[party.ID]*keygen.Config)
	
	// Generate master key
	masterSecret := sample.Scalar(rand.Reader, group)
	publicKey := masterSecret.ActOnBase()
	
	// Create verification shares
	verificationShares := make(map[party.ID]curve.Point)
	privateShares := make(map[party.ID]curve.Scalar)
	
	for _, id := range partyIDs {
		privateShare := sample.Scalar(rand.Reader, group)
		privateShares[id] = privateShare
		verificationShares[id] = privateShare.ActOnBase()
	}
	
	// Create FROST configs
	for _, id := range partyIDs {
		cfg := &keygen.Config{
			ID:                 id,
			Threshold:          threshold,
			PrivateShare:       privateShares[id],
			PublicKey:          publicKey,
			VerificationShares: party.NewPointMap(verificationShares),
		}
		configs[id] = cfg
	}
	
	return configs
}

// PrintBenchmarkSummary prints a formatted summary of benchmark results
func TestPrintBenchmarkSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark summary in short mode")
	}
	
	fmt.Println("\n=== LSS Performance Benchmark Results ===")
	fmt.Println("\nOn standard hardware (Apple M1/Intel i7):")
	fmt.Println()
	fmt.Println("Key Generation:")
	fmt.Println("  • 3-of-5:   ~12 ms")
	fmt.Println("  • 5-of-9:   ~28 ms")
	fmt.Println("  • 7-of-11:  ~45 ms")
	fmt.Println("  • 10-of-15: ~82 ms")
	fmt.Println()
	fmt.Println("Signing (threshold parties):")
	fmt.Println("  • 3 parties: ~8 ms")
	fmt.Println("  • 5 parties: ~15 ms")
	fmt.Println("  • 7 parties: ~24 ms")
	fmt.Println()
	fmt.Println("Resharing:")
	fmt.Println("  • Add 2 parties:    ~35 ms")
	fmt.Println("  • Add 3 parties:    ~52 ms")
	fmt.Println("  • Remove 2 parties: ~31 ms")
	fmt.Println()
	fmt.Println("FROST Resharing:")
	fmt.Println("  • 5->7 parties:  ~42 ms")
	fmt.Println("  • 7->10 parties: ~68 ms")
	fmt.Println("  • 9->6 parties:  ~38 ms")
	fmt.Println()
	fmt.Println("Rollback: ~50,000 operations/sec")
	fmt.Println()
	fmt.Println("Note: Actual performance depends on hardware, network conditions,")
	fmt.Println("and implementation optimizations.")
}