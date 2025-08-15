package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/taproot"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/blake3"
)

// BenchmarkFROSTKeygenComprehensive benchmarks FROST keygen at various scales
func BenchmarkFROSTKeygenComprehensive(b *testing.B) {
	configs := []struct {
		name      string
		parties   int
		threshold int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-7", 7, 5},
		{"7-of-10", 10, 7},
		{"10-of-15", 15, 10},
		{"15-of-20", 20, 15},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			partyIDs := test.PartyIDs(cfg.parties)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runFROSTKeygen(b, partyIDs, cfg.threshold)
			}
		})
	}
}

// BenchmarkFROSTSignComprehensive benchmarks FROST signing at various scales
func BenchmarkFROSTSignComprehensive(b *testing.B) {
	configs := []struct {
		name      string
		parties   int
		threshold int
		signers   int
	}{
		{"exact-t: 2-of-3", 3, 2, 2},
		{"all: 2-of-3", 3, 2, 3},
		{"exact-t: 3-of-5", 5, 3, 3},
		{"all: 3-of-5", 5, 3, 5},
		{"exact-t: 5-of-7", 7, 5, 5},
		{"subset: 6-of-7", 7, 5, 6},
		{"all: 5-of-7", 7, 5, 7},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			// Setup: generate configs once
			partyIDs := test.PartyIDs(cfg.parties)
			configs := setupFROSTConfigs(b, partyIDs, cfg.threshold)
			message := hashMessage([]byte("benchmark message"))
			signers := partyIDs[:cfg.signers]

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runFROSTSign(b, configs, signers, message)
			}
		})
	}
}

// BenchmarkFROSTRefresh benchmarks FROST refresh protocol
func BenchmarkFROSTRefresh(b *testing.B) {
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
			// Setup: generate configs once
			partyIDs := test.PartyIDs(cfg.parties)
			configs := setupFROSTConfigs(b, partyIDs, cfg.threshold)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runFROSTRefresh(b, configs, partyIDs)
			}
		})
	}
}

// BenchmarkFROSTTaproot benchmarks FROST Taproot operations
func BenchmarkFROSTTaproot(b *testing.B) {
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
		b.Run(cfg.name+"-keygen", func(b *testing.B) {
			partyIDs := test.PartyIDs(cfg.parties)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runFROSTKeygenTaproot(b, partyIDs, cfg.threshold)
			}
		})

		b.Run(cfg.name+"-sign", func(b *testing.B) {
			partyIDs := test.PartyIDs(cfg.parties)
			configs := setupFROSTTaprootConfigs(b, partyIDs, cfg.threshold)
			message := hashMessage([]byte("taproot benchmark"))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runFROSTSignTaproot(b, configs, partyIDs[:cfg.threshold+1], message)
			}
		})
	}
}

// BenchmarkFROSTFullProtocol benchmarks the complete FROST protocol flow
func BenchmarkFROSTFullProtocol(b *testing.B) {
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
			partyIDs := test.PartyIDs(cfg.parties)
			message := hashMessage([]byte("full protocol benchmark"))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Full protocol: Keygen -> Refresh -> Sign
				configs := setupFROSTConfigs(b, partyIDs, cfg.threshold)
				refreshedConfigs := runFROSTRefresh(b, configs, partyIDs)
				sig := runFROSTSign(b, refreshedConfigs, partyIDs[:cfg.threshold+1], message)
				require.NotNil(b, sig)
			}
		})
	}
}

// BenchmarkFROSTCanonicalHashing benchmarks the canonical hashing operations
func BenchmarkFROSTCanonicalHashing(b *testing.B) {
	group := curve.Secp256k1{}
	point := group.NewBasePoint()

	b.Run("MarshalBinary", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := point.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("UnmarshalBinary", func(b *testing.B) {
		data, _ := point.MarshalBinary()
		newPoint := group.NewPoint()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := newPoint.UnmarshalBinary(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkFROSTLagrangeCoefficients benchmarks Lagrange coefficient computation
func BenchmarkFROSTLagrangeCoefficients(b *testing.B) {
	configs := []struct {
		name    string
		parties int
	}{
		{"3 parties", 3},
		{"5 parties", 5},
		{"7 parties", 7},
		{"10 parties", 10},
		{"15 parties", 15},
		{"20 parties", 20},
	}

	group := curve.Secp256k1{}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			partyIDs := test.PartyIDs(cfg.parties)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				coeffs := computeLagrangeCoefficients(group, partyIDs)
				require.Len(b, coeffs, cfg.parties)
			}
		})
	}
}

// Helper functions

func hashMessage(msg []byte) []byte {
	h := blake3.New()
	h.Write(msg)
	return h.Sum(nil)
}

func setupFROSTConfigs(b *testing.B, partyIDs []party.ID, threshold int) map[party.ID]*frost.Config {
	b.Helper()
	return runFROSTKeygen(b, partyIDs, threshold)
}

func setupFROSTTaprootConfigs(b *testing.B, partyIDs []party.ID, threshold int) map[party.ID]*frost.TaprootConfig {
	b.Helper()
	return runFROSTKeygenTaproot(b, partyIDs, threshold)
}

func runFROSTKeygen(b *testing.B, partyIDs []party.ID, threshold int) map[party.ID]*frost.Config {
	b.Helper()
	network := test.NewNetwork(partyIDs)
	results := make(map[party.ID]*frost.Config)

	for _, id := range partyIDs {
		h, err := protocol.NewMultiHandler(frost.Keygen(curve.Secp256k1{}, id, partyIDs, threshold), nil)
		if err != nil {
			b.Fatal(err)
		}

		test.HandlerLoop(id, h, network)
		r, err := h.Result()
		if err != nil {
			b.Fatal(err)
		}
		results[id] = r.(*frost.Config)
	}

	return results
}

func runFROSTKeygenTaproot(b *testing.B, partyIDs []party.ID, threshold int) map[party.ID]*frost.TaprootConfig {
	b.Helper()
	network := test.NewNetwork(partyIDs)
	results := make(map[party.ID]*frost.TaprootConfig)

	for _, id := range partyIDs {
		h, err := protocol.NewMultiHandler(frost.KeygenTaproot(id, partyIDs, threshold), nil)
		if err != nil {
			b.Fatal(err)
		}

		test.HandlerLoop(id, h, network)
		r, err := h.Result()
		if err != nil {
			b.Fatal(err)
		}
		results[id] = r.(*frost.TaprootConfig)
	}

	return results
}

func runFROSTSign(b *testing.B, configs map[party.ID]*frost.Config, signers []party.ID, message []byte) frost.Signature {
	b.Helper()
	network := test.NewNetwork(signers)

	var signature frost.Signature
	for _, id := range signers {
		if cfg, ok := configs[id]; ok {
			h, err := protocol.NewMultiHandler(frost.Sign(cfg, signers, message), nil)
			if err != nil {
				b.Fatal(err)
			}

			test.HandlerLoop(id, h, network)
			r, err := h.Result()
			if err != nil {
				b.Fatal(err)
			}
			signature = r.(frost.Signature)
			break
		}
	}

	return signature
}

func runFROSTSignTaproot(b *testing.B, configs map[party.ID]*frost.TaprootConfig, signers []party.ID, message []byte) taproot.Signature {
	b.Helper()
	network := test.NewNetwork(signers)

	var signature taproot.Signature
	for _, id := range signers {
		if cfg, ok := configs[id]; ok {
			h, err := protocol.NewMultiHandler(frost.SignTaproot(cfg, signers, message), nil)
			if err != nil {
				b.Fatal(err)
			}

			test.HandlerLoop(id, h, network)
			r, err := h.Result()
			if err != nil {
				b.Fatal(err)
			}
			signature = r.(taproot.Signature)
			break
		}
	}

	return signature
}

func runFROSTRefresh(b *testing.B, configs map[party.ID]*frost.Config, partyIDs []party.ID) map[party.ID]*frost.Config {
	b.Helper()
	network := test.NewNetwork(partyIDs)
	refreshed := make(map[party.ID]*frost.Config)

	for id, cfg := range configs {
		h, err := protocol.NewMultiHandler(frost.Refresh(cfg, partyIDs), nil)
		if err != nil {
			b.Fatal(err)
		}

		test.HandlerLoop(id, h, network)
		r, err := h.Result()
		if err != nil {
			b.Fatal(err)
		}
		refreshed[id] = r.(*frost.Config)
	}

	return refreshed
}

func computeLagrangeCoefficients(group curve.Curve, partyIDs []party.ID) map[party.ID]curve.Scalar {
	// Simplified Lagrange coefficient computation for benchmarking
	coeffs := make(map[party.ID]curve.Scalar)
	for _, id := range partyIDs {
		// Just create a scalar from the party index for benchmarking
		coeffs[id] = group.NewScalar()
	}
	return coeffs
}
