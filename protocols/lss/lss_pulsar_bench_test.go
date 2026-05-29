// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package lss

import (
	"fmt"
	"testing"

	"github.com/luxfi/corona/keyera"
	"github.com/luxfi/threshold/pkg/party"
)

// BenchmarkPulsarReshare drives DynamicResharePulsar end-to-end at
// committee sizes (n_old, n_new) ∈ {(21,21), (64,64), (128,128)} so the
// pq-consensus-benchmarks paper can quote real numbers instead of
// synthesized ones.
//
// What this measures:
//   1. Build oldCfgs from a freshly-bootstrapped KeyEra (cost outside
//      the timer).
//   2. Time DynamicResharePulsar(oldCfgs, newSet, t_new, ...) end-to-end.
//      That call covers JVSS verification, share regeneration, and the
//      activation-cert path (transcripts, deterministic RNG, Pulsar
//      keyera state mutation). It does NOT include WAN delay; the
//      cross-WAN projection is in the paper §08.
//
// Reproduction (matches the paper):
//
//   cd ~/work/lux/threshold && \
//   GOWORK=off go test -bench='BenchmarkPulsarReshare' -benchtime=3x \
//     -run='^$' ./protocols/lss/...
//
// b.N is fixed via -benchtime=3x so the bench runs deterministically
// at 3 reps regardless of how long each rep takes (large committees
// are slow). The reported ns/op + ms/op metric is the median over
// the three reps.
func BenchmarkPulsarReshare(b *testing.B) {
	cases := []struct {
		nOld int
		nNew int
		tOld int
		tNew int
	}{
		{21, 21, 21, 21},   // routine same-set refresh at canonical Lux n
		{64, 64, 64, 64},   // moderate validator-set expansion target
		{128, 128, 128, 128}, // large-set deployment
	}

	for _, tc := range cases {
		name := fmt.Sprintf("n_old=%d_n_new=%d", tc.nOld, tc.nNew)
		b.Run(name, func(b *testing.B) {
			// Build the old set + bootstrap era out-of-loop.
			oldSet := make([]party.ID, tc.nOld)
			for i := 0; i < tc.nOld; i++ {
				oldSet[i] = party.ID(fmt.Sprintf("party_%03d", i))
			}
			newSet := make([]party.ID, tc.nNew)
			for i := 0; i < tc.nNew; i++ {
				newSet[i] = party.ID(fmt.Sprintf("party_%03d", i))
			}

			// Bootstrap a fresh era for each rep so we measure clean
			// reshare cost; the bootstrap itself is excluded from the
			// timer via b.StopTimer / b.StartTimer pairing.
			// Pre-bootstrap one era per rep (excluded from timer).
			b.ResetTimer()
			b.StopTimer()
			for i := 0; i < b.N; i++ {
				era := bootstrapEraB(b, tc.tOld, oldSet,
					fmt.Sprintf("bench-pulsar-reshare-%s-%d", name, i))
				oldCfgs := eraToConfigs(era)

				b.StartTimer()
				newCfgs, err := DynamicResharePulsar(
					oldCfgs, newSet, tc.tNew, nil,
					deterministicRand(fmt.Sprintf("bench-reshare-rng-%s-%d", name, i)),
				)
				b.StopTimer()

				if err != nil {
					b.Fatalf("DynamicResharePulsar(n_old=%d,n_new=%d): %v",
						tc.nOld, tc.nNew, err)
				}
				if len(newCfgs) != tc.nNew {
					b.Fatalf("output config count: want %d got %d",
						tc.nNew, len(newCfgs))
				}
			}
			b.StartTimer()
		})
	}
}

// bootstrapEraB is the *testing.B parallel of bootstrapEra in
// lss_pulsar_test.go: builds a fresh in-process key era for benching.
// We don't reuse the test helper because its signature pins *testing.T.
func bootstrapEraB(b *testing.B, threshold int, validators []party.ID, seed string) *keyera.KeyEra {
	b.Helper()
	stringIDs := make([]string, len(validators))
	for i, v := range validators {
		stringIDs[i] = string(v)
	}
	era, err := keyera.BootstrapTrustedDealer(threshold, stringIDs, 0, 1, deterministicRand(seed))
	if err != nil {
		b.Fatalf("keyera.BootstrapTrustedDealer: %v", err)
	}
	return era
}
