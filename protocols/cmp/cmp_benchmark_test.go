package cmp_test

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/require"
)

// BenchmarkCMPKeygen benchmarks the CMP key generation protocol
func BenchmarkCMPKeygen(b *testing.B) {
	configs := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-7", 7, 5},
		{"7-of-10", 10, 7},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			partyIDs := test.PartyIDs(cfg.parties)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runCMPKeygen(b, partyIDs, cfg.threshold)
			}
		})
	}
}

// BenchmarkCMPSign benchmarks the CMP signing protocol
func BenchmarkCMPSign(b *testing.B) {
	configs := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-7", 7, 5},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			// Setup: generate configs once
			partyIDs := test.PartyIDs(cfg.parties)
			configs := setupCMPConfigs(b, partyIDs, cfg.threshold)
			message := []byte("benchmark message")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runCMPSign(b, configs, partyIDs[:cfg.threshold+1], message)
			}
		})
	}
}

// BenchmarkCMPPresign benchmarks the CMP presigning protocol
func BenchmarkCMPPresign(b *testing.B) {
	configs := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-7", 7, 5},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			// Setup: generate configs once
			partyIDs := test.PartyIDs(cfg.parties)
			configs := setupCMPConfigs(b, partyIDs, cfg.threshold)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runCMPPresign(b, configs, partyIDs[:cfg.threshold+1])
			}
		})
	}
}

// BenchmarkCMPRefresh benchmarks the CMP refresh protocol
func BenchmarkCMPRefresh(b *testing.B) {
	configs := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-7", 7, 5},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			// Setup: generate configs once
			partyIDs := test.PartyIDs(cfg.parties)
			configs := setupCMPConfigs(b, partyIDs, cfg.threshold)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runCMPRefresh(b, configs)
			}
		})
	}
}

// BenchmarkCMPFullProtocol benchmarks the complete CMP protocol flow
func BenchmarkCMPFullProtocol(b *testing.B) {
	configs := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			partyIDs := test.PartyIDs(cfg.parties)
			message := []byte("benchmark message")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Full protocol: Keygen -> Refresh -> Sign -> Presign -> PresignOnline
				configs := setupCMPConfigs(b, partyIDs, cfg.threshold)
				refreshedConfigs := runCMPRefresh(b, configs)
				sig := runCMPSign(b, refreshedConfigs, partyIDs[:cfg.threshold+1], message)
				require.NotNil(b, sig)
				presig := runCMPPresign(b, refreshedConfigs, partyIDs[:cfg.threshold+1])
				require.NotNil(b, presig)
			}
		})
	}
}

// Helper functions

func setupCMPConfigs(b *testing.B, partyIDs []party.ID, threshold int) map[party.ID]*cmp.Config {
	b.Helper()
	pl := pool.NewPool(0)
	defer pl.TearDown()

	configs, _ := test.GenerateConfig(curve.Secp256k1{}, len(partyIDs), threshold, rand.Reader, pl)
	return configs
}

func runCMPKeygen(b *testing.B, partyIDs []party.ID, threshold int) map[party.ID]*cmp.Config {
	b.Helper()
	network := test.NewNetwork(partyIDs)
	results := make(map[party.ID]*cmp.Config)

	for _, id := range partyIDs {
		pl := pool.NewPool(0)
		defer pl.TearDown()

		h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl), nil)
		if err != nil {
			b.Fatal(err)
		}

		test.HandlerLoop(id, h, network)
		r, err := h.Result()
		if err != nil {
			b.Fatal(err)
		}
		results[id] = r.(*cmp.Config)
	}

	return results
}

func runCMPSign(b *testing.B, configs map[party.ID]*cmp.Config, signers []party.ID, message []byte) *ecdsa.Signature {
	b.Helper()
	network := test.NewNetwork(signers)

	var signature *ecdsa.Signature
	for _, id := range signers {
		if cfg, ok := configs[id]; ok {
			pl := pool.NewPool(0)
			defer pl.TearDown()

			h, err := protocol.NewMultiHandler(cmp.Sign(cfg, signers, message, pl), nil)
			if err != nil {
				b.Fatal(err)
			}

			test.HandlerLoop(id, h, network)
			r, err := h.Result()
			if err != nil {
				b.Fatal(err)
			}
			signature = r.(*ecdsa.Signature)
			break // We only need one signature
		}
	}

	return signature
}

func runCMPPresign(b *testing.B, configs map[party.ID]*cmp.Config, signers []party.ID) *ecdsa.PreSignature {
	b.Helper()
	network := test.NewNetwork(signers)

	var presignature *ecdsa.PreSignature
	for _, id := range signers {
		if cfg, ok := configs[id]; ok {
			pl := pool.NewPool(0)
			defer pl.TearDown()

			h, err := protocol.NewMultiHandler(cmp.Presign(cfg, signers, pl), nil)
			if err != nil {
				b.Fatal(err)
			}

			test.HandlerLoop(id, h, network)
			r, err := h.Result()
			if err != nil {
				b.Fatal(err)
			}
			presignature = r.(*ecdsa.PreSignature)
			break
		}
	}

	return presignature
}

func runCMPRefresh(b *testing.B, configs map[party.ID]*cmp.Config) map[party.ID]*cmp.Config {
	b.Helper()
	partyIDs := make([]party.ID, 0, len(configs))
	for id := range configs {
		partyIDs = append(partyIDs, id)
	}

	network := test.NewNetwork(partyIDs)
	refreshed := make(map[party.ID]*cmp.Config)

	for id, cfg := range configs {
		pl := pool.NewPool(0)
		defer pl.TearDown()

		h, err := protocol.NewMultiHandler(cmp.Refresh(cfg, pl), nil)
		if err != nil {
			b.Fatal(err)
		}

		test.HandlerLoop(id, h, network)
		r, err := h.Result()
		if err != nil {
			b.Fatal(err)
		}
		refreshed[id] = r.(*cmp.Config)
	}

	return refreshed
}
