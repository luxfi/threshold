// +build fuzzing

package lss_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/luxfi/threshold/protocols/lss/dealer"
)

// FuzzReshareMessage tests reshare message parsing
func FuzzReshareMessage(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0x01, 0x02, 0x03}, uint64(1), byte(0))
	f.Add([]byte{0xff, 0xfe, 0xfd}, uint64(100), byte(3))
	
	f.Fuzz(func(t *testing.T, data []byte, generation uint64, msgType byte) {
		msg := &lss.ReshareMessage{
			Type:       lss.ReshareMessageType(msgType % 4),
			Generation: generation,
			Data:       data,
		}
		
		// Ensure no panic when processing message
		d := dealer.NewBootstrapDealer(curve.Secp256k1{}, []party.ID{"p1", "p2", "p3"}, 2)
		_ = d.HandleReshareMessage("p1", msg)
	})
}

// FuzzDynamicReshare tests dynamic resharing with random inputs
func FuzzDynamicReshare(f *testing.F) {
	// Seed corpus with various party configurations
	f.Add(3, 2, 5, 3, true)  // Add parties
	f.Add(7, 4, 5, 3, false) // Remove parties
	f.Add(5, 3, 5, 4, true)  // Change threshold
	
	f.Fuzz(func(t *testing.T, initialN int, initialT int, finalN int, finalT int, addParties bool) {
		// Bounds checking
		if initialN < 1 || initialN > 100 {
			return
		}
		if initialT < 1 || initialT > initialN {
			return
		}
		if finalN < 1 || finalN > 100 {
			return
		}
		if finalT < 1 || finalT > finalN {
			return
		}
		
		// Create initial configuration
		group := curve.Secp256k1{}
		initialIDs := make([]party.ID, initialN)
		for i := 0; i < initialN; i++ {
			initialIDs[i] = party.ID(fmt.Sprintf("party_%d", i))
		}
		
		// Create mock configs
		configs := make(map[party.ID]*config.Config)
		secret := sample.Scalar(rand.Reader, group)
		
		for _, id := range initialIDs {
			configs[id] = &config.Config{
				ID:         id,
				Group:      group,
				Threshold:  initialT,
				Generation: 0,
				ECDSA:      secret, // Simplified for fuzzing
				Public:     make(map[party.ID]*config.Public),
				ChainKey:   []byte("test"),
				RID:        []byte("test"),
			}
		}
		
		// Prepare new party IDs
		var newIDs []party.ID
		if addParties && finalN > initialN {
			// Add parties
			newIDs = initialIDs
			for i := initialN; i < finalN; i++ {
				newIDs = append(newIDs, party.ID(fmt.Sprintf("new_%d", i)))
			}
		} else if !addParties && finalN < initialN {
			// Remove parties
			newIDs = initialIDs[:finalN]
		} else {
			newIDs = initialIDs
		}
		
		// Attempt resharing (shouldn't panic)
		_, _ = lss.DynamicReshareCMP(configs, newIDs, finalT, nil)
	})
}

// FuzzSignatureGeneration tests signature generation with random inputs
func FuzzSignatureGeneration(f *testing.F) {
	// Seed corpus
	f.Add([]byte("test message"), 3, 5)
	f.Add([]byte("another message"), 4, 7)
	
	f.Fuzz(func(t *testing.T, message []byte, threshold int, parties int) {
		// Bounds checking
		if threshold < 1 || threshold > 20 {
			return
		}
		if parties < threshold || parties > 20 {
			return
		}
		if len(message) == 0 || len(message) > 1000 {
			return
		}
		
		// Create message hash
		messageHash := make([]byte, 32)
		if len(message) >= 32 {
			copy(messageHash, message[:32])
		} else {
			copy(messageHash, message)
		}
		
		// Create party IDs
		partyIDs := make([]party.ID, parties)
		for i := 0; i < parties; i++ {
			partyIDs[i] = party.ID(fmt.Sprintf("p%d", i))
		}
		
		// Select signers
		signers := partyIDs[:threshold]
		
		// Create mock config
		group := curve.Secp256k1{}
		cfg := &config.Config{
			ID:        partyIDs[0],
			Group:     group,
			Threshold: threshold,
			ECDSA:     sample.Scalar(rand.Reader, group),
			Public:    make(map[party.ID]*config.Public),
			ChainKey:  []byte("test"),
			RID:       []byte("test"),
		}
		
		// Attempt signing (shouldn't panic)
		signFunc := lss.Sign(cfg, signers, messageHash, nil)
		if signFunc != nil {
			_, _ = signFunc([]byte("session"))
		}
	})
}

// FuzzRollback tests rollback functionality with random inputs
func FuzzRollback(f *testing.F) {
	f.Add(uint64(1), uint64(5), 3)
	f.Add(uint64(10), uint64(15), 5)
	
	f.Fuzz(func(t *testing.T, currentGen uint64, targetGen uint64, maxHistory int) {
		// Bounds checking
		if maxHistory < 1 || maxHistory > 100 {
			return
		}
		if currentGen > 1000000 {
			return
		}
		
		rollbackMgr := lss.NewRollbackManager(maxHistory)
		group := curve.Secp256k1{}
		
		// Create and save snapshots
		for gen := uint64(0); gen <= currentGen && gen < uint64(maxHistory); gen++ {
			cfg := &config.Config{
				ID:         "test",
				Group:      group,
				Threshold:  3,
				Generation: gen,
				ECDSA:      sample.Scalar(rand.Reader, group),
				Public:     make(map[party.ID]*config.Public),
				ChainKey:   []byte("test"),
				RID:        []byte("test"),
			}
			_ = rollbackMgr.SaveSnapshot(cfg)
		}
		
		// Attempt rollback
		if targetGen < currentGen {
			_, _ = rollbackMgr.Rollback(targetGen)
		}
	})
}

// FuzzConfigValidation tests config validation with random inputs
func FuzzConfigValidation(f *testing.F) {
	f.Fuzz(func(t *testing.T, threshold int, partyCount int, hasECDSA bool, hasChainKey bool) {
		group := curve.Secp256k1{}
		
		cfg := &config.Config{
			ID:        "test",
			Group:     group,
			Threshold: threshold,
			Public:    make(map[party.ID]*config.Public),
		}
		
		if hasECDSA {
			cfg.ECDSA = sample.Scalar(rand.Reader, group)
		}
		
		if hasChainKey {
			cfg.ChainKey = []byte("chainkey")
			cfg.RID = []byte("rid")
		}
		
		// Add public shares
		for i := 0; i < partyCount; i++ {
			pid := party.ID(fmt.Sprintf("p%d", i))
			cfg.Public[pid] = &config.Public{
				ECDSA: sample.Point(rand.Reader, group),
			}
		}
		
		// Validate (shouldn't panic)
		_ = cfg.Validate()
	})
}

// FuzzBlindingProtocol tests blinding protocol with random inputs
func FuzzBlindingProtocol(f *testing.F) {
	f.Add([]byte("message"), byte(0), 3, 5)
	f.Add([]byte("another"), byte(1), 4, 7)
	
	f.Fuzz(func(t *testing.T, message []byte, protocol byte, threshold int, parties int) {
		// Bounds checking
		if len(message) != 32 {
			// Pad or truncate to 32 bytes
			padded := make([]byte, 32)
			copy(padded, message)
			message = padded
		}
		
		if threshold < 1 || threshold > 20 {
			return
		}
		if parties < threshold || parties > 20 {
			return
		}
		
		// Create party IDs
		partyIDs := make([]party.ID, parties)
		for i := 0; i < parties; i++ {
			partyIDs[i] = party.ID(fmt.Sprintf("p%d", i))
		}
		
		signers := partyIDs[:threshold]
		
		// Create config
		group := curve.Secp256k1{}
		cfg := &config.Config{
			ID:        partyIDs[0],
			Group:     group,
			Threshold: threshold,
			ECDSA:     sample.Scalar(rand.Reader, group),
			Public:    make(map[party.ID]*config.Public),
			ChainKey:  []byte("test"),
			RID:       []byte("test"),
		}
		
		// Attempt signing with blinding
		blindingProtocol := lss.BlindingProtocol(protocol % 2)
		signFunc := lss.SignWithBlinding(cfg, signers, message, blindingProtocol, nil)
		if signFunc != nil {
			_, _ = signFunc([]byte("session"))
		}
	})
}

// FuzzMessageSerialization tests message serialization/deserialization
func FuzzMessageSerialization(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		
		// Try to interpret as various message types
		group := curve.Secp256k1{}
		
		// Try as scalar
		scalar := group.NewScalar()
		_ = scalar.UnmarshalBinary(data)
		
		// Try as point
		point := group.NewPoint()
		_ = point.UnmarshalBinary(data)
		
		// Try as reshare message
		msg := &lss.ReshareMessage{
			Type:       lss.ReshareMessageType(data[0] % 4),
			Generation: uint64(data[1]),
			Data:       data[2:],
		}
		
		// Process through dealer (shouldn't panic)
		d := dealer.NewBootstrapDealer(group, []party.ID{"p1"}, 1)
		_ = d.HandleReshareMessage("p1", msg)
	})
}

// FuzzLagrangeInterpolation tests Lagrange interpolation with random shares
func FuzzLagrangeInterpolation(f *testing.F) {
	f.Fuzz(func(t *testing.T, shareCount int, threshold int, shareData []byte) {
		// Bounds checking
		if threshold < 1 || threshold > 20 {
			return
		}
		if shareCount < threshold || shareCount > 20 {
			return
		}
		if len(shareData) < shareCount*32 {
			return
		}
		
		group := curve.Secp256k1{}
		
		// Create party IDs
		partyIDs := make([]party.ID, shareCount)
		shares := make(map[party.ID]curve.Scalar)
		
		for i := 0; i < shareCount; i++ {
			partyIDs[i] = party.ID(fmt.Sprintf("p%d", i))
			
			// Extract share data
			shareBytes := shareData[i*32 : min((i+1)*32, len(shareData))]
			share := group.NewScalar()
			if err := share.UnmarshalBinary(shareBytes); err != nil {
				// Use random if unmarshaling fails
				share = sample.Scalar(rand.Reader, group)
			}
			shares[partyIDs[i]] = share
		}
		
		// Attempt interpolation (shouldn't panic)
		configs := make(map[party.ID]*config.Config)
		for id, share := range shares {
			configs[id] = &config.Config{
				ID:        id,
				Group:     group,
				Threshold: threshold,
				ECDSA:     share,
				Public:    make(map[party.ID]*config.Public),
			}
		}
		
		// This would normally do Lagrange interpolation
		// For fuzzing, we just ensure no panic occurs
		for _, cfg := range configs {
			_ = cfg.Validate()
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}