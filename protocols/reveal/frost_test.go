package reveal_test

// The primitive against a REAL share set.
//
// Everything in reveal_test.go deals its own shares, which proves the algebra
// but not that the algebra matches what the DKG actually produces. A share set
// is a polynomial evaluated at party indices, and the one thing that has to
// agree between the DKG, the Lagrange helper and this protocol is WHICH index —
// disagree and every open silently yields the wrong point.
//
// So this runs the keygen the fleet runs, and opens with what it hands back.

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/reveal"
)

func TestARealKeygensSharesOpenIt(t *testing.T) {
	const n, threshold = 3, 2

	var configs map[party.ID]*frost.Config
	pt := &test.ProtocolTest{
		Name:       "reveal-over-frost",
		PartyCount: n,
		Threshold:  threshold,
		SessionID:  []byte("reveal-over-frost"),
		CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
			return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
		},
		Validate: func(t *testing.T, results map[party.ID]interface{}) {
			configs = make(map[party.ID]*frost.Config, len(results))
			for id, r := range results {
				c, ok := r.(*frost.Config)
				if !ok {
					t.Fatalf("party %s produced %T", id, r)
				}
				configs[id] = c
			}
		},
	}
	pt.Run(t)

	if len(configs) != n {
		t.Fatalf("keygen produced %d configs, want %d", len(configs), n)
	}

	var any *frost.Config
	for _, c := range configs {
		any = c
		break
	}

	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	ct, err := reveal.Encrypt(rand.Reader, any.PublicKey, root)
	if err != nil {
		t.Fatal(err)
	}

	// threshold+1 of the real parties answer with their real shares.
	var answers []*reveal.Answer
	for id, c := range configs {
		if len(answers) == threshold+1 {
			break
		}
		a, err := ct.Answer(rand.Reader, id, c.PrivateShare)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, a)
	}

	got, err := reveal.Open(ct, threshold, any.VerificationShares, answers)
	if err != nil {
		t.Fatalf("open with real shares: %v", err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("the root did not survive a real share set")
	}

	// And threshold alone still does not.
	if _, err := reveal.Open(ct, threshold, any.VerificationShares, answers[:threshold]); err == nil {
		t.Fatal("threshold parties opened it")
	}
}
