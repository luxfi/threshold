package frost_test

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/zeebo/blake3"
)

// ============================================================
// FULL PROTOCOL BENCHMARKS (concurrent handlers, real execution)
// ============================================================

func concurrentFROSTKeygen(t *testing.T, partyIDs []party.ID, threshold int) map[party.ID]*frost.Config {
	t.Helper()
	network := test.NewNetwork(partyIDs)
	results := make(map[party.ID]*frost.Config)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, id := range partyIDs {
		wg.Add(1)
		go func(pid party.ID) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(frost.Keygen(curve.Secp256k1{}, pid, partyIDs, threshold), nil)
			if err != nil {
				t.Errorf("keygen handler error: %v", err)
				return
			}
			test.HandlerLoop(pid, h, network)
			r, err := h.Result()
			if err != nil {
				t.Errorf("keygen result error for %s: %v", pid, err)
				return
			}
			mu.Lock()
			results[pid] = r.(*frost.Config)
			mu.Unlock()
		}(id)
	}

	wg.Wait()
	return results
}

func concurrentFROSTSign(t *testing.T, configs map[party.ID]*frost.Config, signers []party.ID, message []byte) {
	t.Helper()
	network := test.NewNetwork(signers)
	var wg sync.WaitGroup

	for _, id := range signers {
		cfg, ok := configs[id]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(pid party.ID, c *frost.Config) {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(frost.Sign(c, signers, message), nil)
			if err != nil {
				t.Errorf("sign handler error: %v", err)
				return
			}
			test.HandlerLoop(pid, h, network)
			_, err = h.Result()
			if err != nil {
				t.Errorf("sign result error for %s: %v", pid, err)
			}
		}(id, cfg)
	}

	wg.Wait()
}

// TestScaleBenchmarkKeygen runs FROST keygen at increasing party counts
func TestScaleBenchmarkKeygen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale benchmarks in short mode")
	}

	configs := []struct {
		parties   int
		threshold int
	}{
		{3, 2},
		{5, 3},
		{10, 7},
		{15, 10},
		{20, 14},
		{30, 20},
		{50, 34},
	}

	fmt.Println("\n=== FROST Keygen Scale Benchmark ===")
	fmt.Printf("%-12s %-12s %-15s %-15s\n", "Parties", "Threshold", "Time (ms)", "Per-Party (ms)")
	fmt.Println("-----------------------------------------------------------")

	for _, cfg := range configs {
		partyIDs := test.PartyIDs(cfg.parties)

		start := time.Now()
		results := concurrentFROSTKeygen(t, partyIDs, cfg.threshold)
		elapsed := time.Since(start)

		if len(results) != cfg.parties {
			t.Errorf("expected %d results, got %d", cfg.parties, len(results))
			continue
		}

		perParty := float64(elapsed.Milliseconds()) / float64(cfg.parties)
		fmt.Printf("%-12d %-12d %-15.1f %-15.2f\n", cfg.parties, cfg.threshold, float64(elapsed.Milliseconds()), perParty)

		// Quick verify: sign with threshold+1 signers
		msg := hashMsg([]byte("verify"))
		signers := partyIDs[:cfg.threshold+1]
		concurrentFROSTSign(t, results, signers, msg)
	}
}

// TestScaleBenchmarkSigning runs FROST signing at increasing signer counts
func TestScaleBenchmarkSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale benchmarks in short mode")
	}

	// Run signing benchmarks at various scales
	// Each uses a different keygen with threshold = signerCount - 1
	signingConfigs := []struct {
		parties   int
		threshold int
		signers   int
	}{
		{5, 2, 3},
		{8, 4, 5},
		{12, 6, 7},
		{15, 9, 10},
		{20, 14, 15},
		{25, 19, 20},
		{30, 19, 20}, // sign with 20 from 30 total
	}

	iterations := 3

	fmt.Println("\n=== FROST Signing Scale Benchmark ===")
	fmt.Printf("%-12s %-12s %-12s %-15s %-15s %-15s\n", "Total (n)", "Threshold", "Signers", "Avg (ms)", "Min (ms)", "Max (ms)")
	fmt.Println("------------------------------------------------------------------------")

	for _, cfg := range signingConfigs {
		partyIDs := test.PartyIDs(cfg.parties)

		fmt.Printf("Generating keys for %d-of-%d...", cfg.threshold, cfg.parties)
		start := time.Now()
		configs := concurrentFROSTKeygen(t, partyIDs, cfg.threshold)
		fmt.Printf(" done in %v\n", time.Since(start))

		if len(configs) != cfg.parties {
			t.Errorf("keygen failed: got %d configs, want %d", len(configs), cfg.parties)
			continue
		}

		message := hashMsg([]byte("scale benchmark message"))
		signers := partyIDs[:cfg.signers]
		var totalMs, minMs, maxMs float64
		minMs = 999999

		for iter := 0; iter < iterations; iter++ {
			iterStart := time.Now()
			concurrentFROSTSign(t, configs, signers, message)
			iterMs := float64(time.Since(iterStart).Microseconds()) / 1000.0

			totalMs += iterMs
			if iterMs < minMs {
				minMs = iterMs
			}
			if iterMs > maxMs {
				maxMs = iterMs
			}
		}

		avgMs := totalMs / float64(iterations)
		fmt.Printf("%-12d %-12d %-12d %-15.2f %-15.2f %-15.2f\n", cfg.parties, cfg.threshold, cfg.signers, avgMs, minMs, maxMs)
	}
}

// ============================================================
// CRYPTOGRAPHIC PRIMITIVE BENCHMARKS (scales to 10,000+)
// ============================================================

func TestScaleBenchmarkCryptoPrimitives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale benchmarks in short mode")
	}

	group := curve.Secp256k1{}
	scales := []int{10, 100, 1000, 10000}

	fmt.Println("\n=== Crypto Primitive Scale Benchmarks (secp256k1) ===")

	// 1. Scalar multiplication
	fmt.Println("\n--- Scalar Base Multiplication (per-party keygen cost) ---")
	fmt.Printf("%-12s %-15s %-15s\n", "Operations", "Total (ms)", "Per-Op (us)")
	fmt.Println("-------------------------------------------")

	for _, n := range scales {
		scalars := make([]curve.Scalar, n)
		for i := 0; i < n; i++ {
			scalars[i] = sample.Scalar(rand.Reader, group)
		}

		start := time.Now()
		for i := 0; i < n; i++ {
			_ = scalars[i].ActOnBase()
		}
		elapsed := time.Since(start)
		perOp := float64(elapsed.Microseconds()) / float64(n)
		fmt.Printf("%-12d %-15.2f %-15.2f\n", n, float64(elapsed.Microseconds())/1000.0, perOp)
	}

	// 2. Point addition
	fmt.Println("\n--- Point Addition (signature/share aggregation) ---")
	fmt.Printf("%-12s %-15s %-15s\n", "Operations", "Total (ms)", "Per-Op (us)")
	fmt.Println("-------------------------------------------")

	for _, n := range scales {
		points := make([]curve.Point, n)
		for i := 0; i < n; i++ {
			s := sample.Scalar(rand.Reader, group)
			points[i] = s.ActOnBase()
		}

		start := time.Now()
		acc := points[0]
		for i := 1; i < n; i++ {
			acc = acc.Add(points[i])
		}
		elapsed := time.Since(start)
		perOp := float64(elapsed.Microseconds()) / float64(n)
		fmt.Printf("%-12d %-15.2f %-15.2f\n", n, float64(elapsed.Microseconds())/1000.0, perOp)
	}

	// 3. Lagrange interpolation coefficients
	fmt.Println("\n--- Lagrange Coefficient Computation (signing setup) ---")
	fmt.Printf("%-12s %-15s %-15s\n", "Parties", "Total (ms)", "Per-Party (us)")
	fmt.Println("-------------------------------------------")

	for _, n := range scales {
		partyScalars := make([]curve.Scalar, n)
		for i := 0; i < n; i++ {
			s := group.NewScalar()
			buf := make([]byte, 32)
			buf[31] = byte((i + 1) & 0xFF)
			buf[30] = byte(((i + 1) >> 8) & 0xFF)
			s.UnmarshalBinary(buf)
			partyScalars[i] = s
		}

		start := time.Now()
		for i := 0; i < n; i++ {
			num := sample.Scalar(rand.Reader, group)
			for j := 0; j < n; j++ {
				if i == j {
					continue
				}
				diff := group.NewScalar().Set(partyScalars[j]).Sub(partyScalars[i])
				_ = diff.Invert()
				num = num.Mul(partyScalars[j]).Mul(diff)
			}
		}
		elapsed := time.Since(start)
		perParty := float64(elapsed.Microseconds()) / float64(n)
		fmt.Printf("%-12d %-15.2f %-15.2f\n", n, float64(elapsed.Microseconds())/1000.0, perParty)
	}

	// 4. Polynomial evaluation
	fmt.Println("\n--- Polynomial Evaluation (keygen share distribution) ---")
	fmt.Printf("%-12s %-10s %-15s %-15s\n", "Parties", "Degree", "Total (ms)", "Per-Eval (us)")
	fmt.Println("-------------------------------------------------------")

	thresholds := []int{7, 67, 667, 6667}
	for idx, n := range scales {
		tVal := thresholds[idx]
		if tVal >= n {
			tVal = n - 1
		}

		coeffs := make([]curve.Scalar, tVal)
		for i := 0; i < tVal; i++ {
			coeffs[i] = sample.Scalar(rand.Reader, group)
		}

		points := make([]curve.Scalar, n)
		for i := 0; i < n; i++ {
			points[i] = sample.Scalar(rand.Reader, group)
		}

		start := time.Now()
		for i := 0; i < n; i++ {
			result := group.NewScalar().Set(coeffs[tVal-1])
			for j := tVal - 2; j >= 0; j-- {
				result = result.Mul(points[i]).Add(coeffs[j])
			}
			_ = result
		}
		elapsed := time.Since(start)
		perEval := float64(elapsed.Microseconds()) / float64(n)
		fmt.Printf("%-12d %-10d %-15.2f %-15.2f\n", n, tVal, float64(elapsed.Microseconds())/1000.0, perEval)
	}

	// 5. Blake3 hashing
	fmt.Println("\n--- Blake3 Hashing (nonce/challenge generation) ---")
	fmt.Printf("%-12s %-15s %-15s\n", "Operations", "Total (ms)", "Per-Op (us)")
	fmt.Println("-------------------------------------------")

	for _, n := range scales {
		data := make([]byte, 64)
		rand.Read(data)

		start := time.Now()
		for i := 0; i < n; i++ {
			h := blake3.New()
			h.Write(data)
			_ = h.Sum(nil)
		}
		elapsed := time.Since(start)
		perOp := float64(elapsed.Microseconds()) / float64(n)
		fmt.Printf("%-12d %-15.2f %-15.2f\n", n, float64(elapsed.Microseconds())/1000.0, perOp)
	}
}

// TestScaleSummary prints a comprehensive performance summary
func TestScaleSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping")
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("  HANZO MPC — PERFORMANCE SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
	fmt.Println("Signing is O(t) — only threshold signers participate.")
	fmt.Println("Keygen/reshare is O(n²) communication, O(n·t) computation.")
	fmt.Println()
	fmt.Println("Run TestScaleBenchmarkKeygen and TestScaleBenchmarkSigning")
	fmt.Println("for full protocol numbers.")
}

func hashMsg(msg []byte) []byte {
	h := blake3.New()
	h.Write(msg)
	return h.Sum(nil)
}
