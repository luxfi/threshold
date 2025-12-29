package sign

import (
	"testing"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

func TestRound1IsBroadcastRound(t *testing.T) {
	cfg := &config.Config{
		ID:        party.ID("a"),
		Group:     curve.Secp256k1{},
		Threshold: 2,
		Public: map[party.ID]*config.Public{
			"a": {ECDSA: curve.Secp256k1{}.NewScalar().ActOnBase()},
			"b": {ECDSA: curve.Secp256k1{}.NewScalar().ActOnBase()},
			"c": {ECDSA: curve.Secp256k1{}.NewScalar().ActOnBase()},
		},
	}

	signers := []party.ID{"a", "b", "c"}
	startFunc := Start(cfg, signers, make([]byte, 32), nil)
	session, err := startFunc([]byte("test"))
	if err != nil {
		t.Fatalf("Failed to start: %v", err)
	}

	// Check if round 1 is a BroadcastRound
	br, isBR := session.(round.BroadcastRound)
	t.Logf("Round 1 implements BroadcastRound: %v", isBR)
	if !isBR {
		t.Fatal("Round 1 should implement BroadcastRound")
	}

	bc := br.BroadcastContent()
	t.Logf("BroadcastContent type: %T", bc)
	if bc == nil {
		t.Fatal("BroadcastContent should not be nil")
	}
}

func TestRound2IsBroadcastRound(t *testing.T) {
	r1 := &round1{
		signers: []party.ID{"a", "b", "c"},
		config: &config.Config{
			ID:        party.ID("a"),
			Group:     curve.Secp256k1{},
			Threshold: 2,
		},
	}

	r2 := &round2{
		round1: r1,
		nonces: make(map[party.ID]curve.Point),
	}

	// Check if round 2 is a BroadcastRound
	var session round.Session = r2
	br, isBR := session.(round.BroadcastRound)
	t.Logf("Round 2 implements BroadcastRound: %v", isBR)
	if !isBR {
		t.Fatal("Round 2 should implement BroadcastRound")
	}

	bc := br.BroadcastContent()
	t.Logf("BroadcastContent type: %T", bc)
	if bc == nil {
		t.Fatal("BroadcastContent should not be nil")
	}
}
