package keygen_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

func TestTraceHandler(t *testing.T) {
	group := curve.Secp256k1{}
	selfID := party.ID("alice")
	participants := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create the first round
	startFunc := keygen.Start(selfID, participants, threshold, group, pl)
	r1, err := startFunc(nil)
	require.NoError(t, err)

	t.Logf("Round1 created: Number=%d, Final=%d", r1.Number(), r1.FinalRoundNumber())
	t.Logf("SelfID=%s, PartyIDs=%v, OtherPartyIDs=%v", 
		r1.SelfID(), r1.PartyIDs(), r1.OtherPartyIDs())

	// Manually finalize round1 to see what it produces
	out := make(chan *round.Message, 10)
	r2, err := r1.Finalize(out)
	close(out)
	
	if err != nil {
		t.Fatalf("Failed to finalize round1: %v", err)
	}

	msgCount := 0
	for msg := range out {
		msgCount++
		t.Logf("Message %d: Broadcast=%v, Round=%d", 
			msgCount, msg.Broadcast, msg.Content.RoundNumber())
	}

	t.Logf("Round1 produced %d messages", msgCount)
	t.Logf("Round2 number: %d", r2.Number())
}