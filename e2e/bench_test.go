// SPDX-License-Identifier: BSD-3-Clause
package e2e

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"
)

// TestProductionValidation_Bench runs N keygen+sign cycles per scheme
// and reports median + p99 wall-clock numbers. Single-process,
// in-memory dispatcher — the same code path mpcd hosts. This is the
// performance signal that goes into the report's per-scheme table.
//
// N is intentionally small for the SLH-DSA-SHAKE-192s and corona
// paths (multi-second per round); the headline numbers are median +
// p99 across whatever N the timeout permits.
func TestProductionValidation_Bench(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bench in -short mode")
	}
	dh := startZapDispatcher(t)
	defer dh.stop()

	type sched struct {
		Name string
		T    int
		N    int
		Iter int
	}
	cases := []sched{
		{Name: "pulsar", T: 3, N: 5, Iter: 5},
		{Name: "magnetar", T: 5, N: 5, Iter: 3}, // SLH-DSA is slow; 3 iter is enough for median
		{Name: "corona", T: 3, N: 5, Iter: 5},
	}

	for _, c := range cases {
		keygenSamples := make([]time.Duration, 0, c.Iter)
		signSamples := make([]time.Duration, 0, c.Iter)
		for i := 0; i < c.Iter; i++ {
			tKg := time.Now()
			kg, err := rpcCall(dh.addr, c.Name+".keygen",
				map[string]any{"threshold": c.T, "participants": c.N})
			dKg := time.Since(tKg)
			if err != nil {
				t.Errorf("[%s] keygen iter %d: %v", c.Name, i, err)
				continue
			}
			keygenSamples = append(keygenSamples, dKg)

			var kgR struct{ PublicKey string }
			_ = json.Unmarshal(kg, &kgR)

			msg := fmt.Sprintf("bench iter %d for %s", i, c.Name)
			tSg := time.Now()
			_, err = rpcCall(dh.addr, c.Name+".sign", map[string]any{
				"messageHex": hex.EncodeToString([]byte(msg)),
				"pubKeyHex":  kgR.PublicKey,
			})
			dSg := time.Since(tSg)
			if err != nil {
				t.Errorf("[%s] sign iter %d: %v", c.Name, i, err)
				continue
			}
			signSamples = append(signSamples, dSg)
		}
		report(t, c.Name+" keygen", keygenSamples)
		report(t, c.Name+" sign  ", signSamples)
	}
}

func report(t *testing.T, label string, s []time.Duration) {
	t.Helper()
	if len(s) == 0 {
		t.Logf("BENCH %s: NO SAMPLES", label)
		return
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	med := s[len(s)/2]
	p99 := s[len(s)-1] // p99 across our small N is the worst sample
	min := s[0]
	max := s[len(s)-1]
	t.Logf("BENCH %s: n=%d min=%.1fms med=%.1fms p99=%.1fms max=%.1fms",
		label, len(s),
		float64(min.Microseconds())/1000.0,
		float64(med.Microseconds())/1000.0,
		float64(p99.Microseconds())/1000.0,
		float64(max.Microseconds())/1000.0,
	)
}
