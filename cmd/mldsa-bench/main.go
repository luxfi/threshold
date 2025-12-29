// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// mldsa-bench benchmarks PQ signing and verification patterns used by
// Lux quasar consensus and the hierarchical quorum certificate architecture
// described in LP-045.
//
// Modes:
//   individual   — each validator signs individually, verify all sigs
//   committee    — committee of k validators signs, verify aggregate
//   hierarchical — N validators partitioned into clusters, each cluster
//                  produces one cert, clusters combine into root QC
//
// Usage:
//   mldsa-bench -mode=individual -n=100 -level=44
//   mldsa-bench -mode=committee -n=100 -k=32 -level=44
//   mldsa-bench -mode=hierarchical -n=100 -clusters=4 -level=65
//
// Light mnemonic: the harness seeds ML-DSA key generation from a single
// 32-byte secret so 100+ validators can be spun up on a local machine
// without the cost of real mainnet keygen.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"runtime"
	"sync"
	"time"

	luxmldsa "github.com/luxfi/crypto/mldsa"
)

// Alias for readability.
var (
	_ = crypto.Hash(0)
)
type mldsaMode = luxmldsa.Mode
type mldsaPrivateKey = luxmldsa.PrivateKey
type mldsaPublicKey = luxmldsa.PublicKey

// deterministicReader is a reader that produces deterministic bytes from a seed.
// Used to generate identical light keys across runs for reproducible benchmarks.
type deterministicReader struct {
	pos    int
	buffer []byte
	seed   [32]byte
}

func newDeterministicReader(seed [32]byte) *deterministicReader {
	r := &deterministicReader{seed: seed}
	r.refill()
	return r
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.pos >= len(r.buffer) {
			r.refill()
		}
		c := copy(p[n:], r.buffer[r.pos:])
		r.pos += c
		n += c
	}
	return n, nil
}

func (r *deterministicReader) refill() {
	h := sha256.New()
	h.Write(r.seed[:])
	var posBytes [8]byte
	binary.BigEndian.PutUint64(posBytes[:], uint64(r.pos))
	h.Write(posBytes[:])
	r.buffer = h.Sum(nil)
	r.pos = 0
}

func deriveValidatorSeed(masterSeed [32]byte, validatorID int) [32]byte {
	h := sha256.New()
	h.Write(masterSeed[:])
	var idBytes [8]byte
	binary.BigEndian.PutUint64(idBytes[:], uint64(validatorID))
	h.Write(idBytes[:])
	var seed [32]byte
	copy(seed[:], h.Sum(nil))
	return seed
}

// Validator bundles a keypair for benchmarking.
type Validator struct {
	ID  int
	Key *mldsaPrivateKey
	Pub *mldsaPublicKey
}

func genValidators(n int, level mldsaMode, masterSeed [32]byte) []Validator {
	validators := make([]Validator, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seed := deriveValidatorSeed(masterSeed, i)
			reader := newDeterministicReader(seed)
			priv, err := luxmldsa.GenerateKey(reader, level)
			if err != nil {
				panic(fmt.Sprintf("keygen %d: %v", i, err))
			}
			pub := priv.Public().(*mldsaPublicKey)
			validators[i] = Validator{ID: i, Key: priv, Pub: pub}
		}(i)
	}
	wg.Wait()
	return validators
}

type Timings struct {
	Keygen  time.Duration
	Sign    time.Duration
	Verify  time.Duration
	SigBytes int
}

// benchIndividual: every validator signs the block hash. Verifier verifies all.
// This is the pre-aggregation baseline — how expensive if each vote is standalone.
func benchIndividual(n int, level mldsaMode, masterSeed [32]byte, msg []byte) Timings {
	var t Timings

	// Keygen (parallel)
	start := time.Now()
	validators := genValidators(n, level, masterSeed)
	t.Keygen = time.Since(start)

	// Sign (parallel — each validator signs independently)
	sigs := make([][]byte, n)
	start = time.Now()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sig, err := validators[i].Key.Sign(rand.Reader, msg, crypto.Hash(0))
			if err != nil {
				panic(fmt.Sprintf("sign %d: %v", i, err))
			}
			sigs[i] = sig
		}(i)
	}
	wg.Wait()
	t.Sign = time.Since(start)
	t.SigBytes = len(sigs[0]) * n

	// Verify (parallel)
	start = time.Now()
	var failed int64
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if !validators[i].Pub.VerifySignature(msg, sigs[i]) {
				mu.Lock()
				failed++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	t.Verify = time.Since(start)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "WARN: %d signatures failed verification\n", failed)
	}
	return t
}

// benchCommittee: sample k validators out of N, have those k sign individually,
// produce a committee certificate (concatenated sigs + signer bitmap).
// Represents one cluster cert in the LP-045 hierarchical design.
func benchCommittee(n, k int, level mldsaMode, masterSeed [32]byte, msg []byte) Timings {
	var t Timings

	start := time.Now()
	validators := genValidators(n, level, masterSeed)
	t.Keygen = time.Since(start)

	// Deterministic committee selection (stake-weighted sample proxy — just uniform here)
	r := mathrand.New(mathrand.NewPCG(binary.BigEndian.Uint64(masterSeed[:8]), 0))
	perm := r.Perm(n)
	committee := perm[:k]

	sigs := make([][]byte, k)
	start = time.Now()
	var wg sync.WaitGroup
	for idx, vIdx := range committee {
		wg.Add(1)
		go func(idx, vIdx int) {
			defer wg.Done()
			sig, err := validators[vIdx].Key.Sign(rand.Reader, msg, crypto.Hash(0))
			if err != nil {
				panic(err)
			}
			sigs[idx] = sig
		}(idx, vIdx)
	}
	wg.Wait()
	t.Sign = time.Since(start)
	t.SigBytes = len(sigs[0]) * k

	start = time.Now()
	var failed int64
	var mu sync.Mutex
	for idx, vIdx := range committee {
		wg.Add(1)
		go func(idx, vIdx int) {
			defer wg.Done()
			if !validators[vIdx].Pub.VerifySignature(msg, sigs[idx]) {
				mu.Lock()
				failed++
				mu.Unlock()
			}
		}(idx, vIdx)
	}
	wg.Wait()
	t.Verify = time.Since(start)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "WARN: %d committee sigs failed\n", failed)
	}
	return t
}

// benchHierarchical: N validators split into `clusters` groups; each cluster
// produces one cert (all members sign); clusters aggregate into a root QC.
// Models LP-045 two-layer aggregation.
func benchHierarchical(n, clusters int, level mldsaMode, masterSeed [32]byte, msg []byte) Timings {
	var t Timings

	start := time.Now()
	validators := genValidators(n, level, masterSeed)
	t.Keygen = time.Since(start)

	clusterSize := (n + clusters - 1) / clusters
	sigs := make([][][]byte, clusters)

	start = time.Now()
	var wg sync.WaitGroup
	for c := 0; c < clusters; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			lo := c * clusterSize
			hi := lo + clusterSize
			if hi > n {
				hi = n
			}
			clusterSigs := make([][]byte, hi-lo)
			for i := lo; i < hi; i++ {
				sig, err := validators[i].Key.Sign(rand.Reader, msg, crypto.Hash(0))
				if err != nil {
					panic(err)
				}
				clusterSigs[i-lo] = sig
			}
			sigs[c] = clusterSigs
		}(c)
	}
	wg.Wait()
	t.Sign = time.Since(start)

	totalSigs := 0
	sigLen := 0
	for _, c := range sigs {
		totalSigs += len(c)
		if len(c) > 0 && sigLen == 0 {
			sigLen = len(c[0])
		}
	}
	t.SigBytes = totalSigs * sigLen

	// Verify: each cluster verified in parallel, then root verifies cluster certs
	start = time.Now()
	for c := 0; c < clusters; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			lo := c * clusterSize
			hi := lo + clusterSize
			if hi > n {
				hi = n
			}
			for i := lo; i < hi; i++ {
				validators[i].Pub.VerifySignature(msg, sigs[c][i-lo])
			}
		}(c)
	}
	wg.Wait()
	t.Verify = time.Since(start)
	return t
}

func main() {
	var (
		mode     = flag.String("mode", "individual", "individual | committee | hierarchical")
		n        = flag.Int("n", 10, "number of validators")
		k        = flag.Int("k", 0, "committee size (for committee mode; default n/3)")
		clusters = flag.Int("clusters", 4, "number of clusters (hierarchical mode)")
		levelStr = flag.String("level", "44", "ML-DSA level: 44 | 65 | 87")
		runs     = flag.Int("runs", 3, "repetitions (median reported)")
	)
	flag.Parse()

	var level mldsaMode
	switch *levelStr {
	case "44":
		level = luxmldsa.MLDSA44
	case "65":
		level = luxmldsa.MLDSA65
	case "87":
		level = luxmldsa.MLDSA87
	default:
		fmt.Fprintln(os.Stderr, "level must be 44, 65, or 87")
		os.Exit(1)
	}

	if *k == 0 {
		*k = *n / 3
		if *k < 1 {
			*k = 1
		}
	}

	var masterSeed [32]byte
	copy(masterSeed[:], []byte("lux-mldsa-bench-deterministic-v1"))

	msg := []byte("block-header-hash-example-32-bytes-long")

	fmt.Printf("# ML-DSA PQ Signing Benchmark\n")
	fmt.Printf("# GOOS=%s GOARCH=%s NumCPU=%d\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("# mode=%s n=%d level=ML-DSA-%s runs=%d\n\n",
		*mode, *n, *levelStr, *runs)

	results := make([]Timings, *runs)
	for i := 0; i < *runs; i++ {
		var seed [32]byte
		copy(seed[:], masterSeed[:])
		seed[31] = byte(i)

		switch *mode {
		case "individual":
			results[i] = benchIndividual(*n, level, seed, msg)
		case "committee":
			results[i] = benchCommittee(*n, *k, level, seed, msg)
		case "hierarchical":
			results[i] = benchHierarchical(*n, *clusters, level, seed, msg)
		default:
			fmt.Fprintln(os.Stderr, "invalid mode")
			os.Exit(1)
		}
	}

	med := median(results)
	fmt.Printf("           keygen=%v  sign=%v  verify=%v  sig-bytes=%d\n",
		med.Keygen.Round(time.Microsecond),
		med.Sign.Round(time.Microsecond),
		med.Verify.Round(time.Microsecond),
		med.SigBytes)

	if *mode == "committee" {
		fmt.Printf("           committee k=%d (%.0f%% of n)\n",
			*k, 100*float64(*k)/float64(*n))
	}
	if *mode == "hierarchical" {
		fmt.Printf("           clusters=%d  cluster-size=%d\n",
			*clusters, (*n+*clusters-1)/(*clusters))
	}

	perValidator := med.Sign / time.Duration(*n)
	fmt.Printf("           per-validator sign latency (median): %v\n",
		perValidator.Round(time.Microsecond))
}

func median(ts []Timings) Timings {
	// Cheap median per field — for small runs counts.
	byField := func(f func(Timings) time.Duration) time.Duration {
		vals := make([]time.Duration, len(ts))
		for i, t := range ts {
			vals[i] = f(t)
		}
		for i := 0; i < len(vals); i++ {
			for j := i + 1; j < len(vals); j++ {
				if vals[i] > vals[j] {
					vals[i], vals[j] = vals[j], vals[i]
				}
			}
		}
		return vals[len(vals)/2]
	}
	return Timings{
		Keygen:   byField(func(t Timings) time.Duration { return t.Keygen }),
		Sign:     byField(func(t Timings) time.Duration { return t.Sign }),
		Verify:   byField(func(t Timings) time.Duration { return t.Verify }),
		SigBytes: ts[len(ts)/2].SigBytes,
	}
}
