package reshare_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/luxfi/threshold/protocols/lss/reshare"
	"github.com/luxfi/threshold/protocols/lss/sign"
)

// RESHARING MEANS THE KEY SURVIVES A CHANGE OF SHARES. Every round here was at
// zero coverage — the tests built a session and asserted it was non-nil — so
// nothing had produced a new share, and round 3's own key-preservation check
// had never run. When it finally did, it refused: the reshare had changed the
// key twice over.
//
// The strong property is not that the new public shares interpolate to the old
// key, which is what that internal check compares. It is that the new PRIVATE
// shares still sign for it, which only a signature can show.
func TestReshareKeepsTheKeyAndTheNewSharesCanSign(t *testing.T) {
	ids := []party.ID{"alice", "bob", "charlie"}
	configs, publicKey := test.SharedLSSConfigs(ids, 1, rand.Reader)

	pl := pool.NewPool(0)
	defer pl.TearDown()

	results, err := test.RunProtocol(t, ids, []byte("lss-reshare-session"), func(id party.ID) protocol.StartFunc {
		return reshare.Start(configs[id], ids, 2, pl)
	})
	if err != nil {
		t.Fatalf("resharing did not complete: %v", err)
	}

	fresh := make(map[party.ID]*config.Config, len(ids))
	for id, res := range results {
		cfg, ok := res.(*config.Config)
		if !ok {
			t.Fatalf("%s returned %T, not a config", id, res)
		}
		got, err := cfg.PublicPoint()
		if err != nil {
			t.Fatalf("%s: public point: %v", id, err)
		}
		if !got.Equal(publicKey) {
			t.Errorf("%s: the group key changed across the reshare", id)
		}
		if cfg.ECDSA.Equal(configs[id].ECDSA) {
			t.Errorf("%s: the share is unchanged, so nothing was reshared", id)
		}
		// The share and its own public share must agree, or the sharing is
		// two different secrets wearing one key: the public shares interpolate
		// to the old key while the private ones sign for something else.
		if want := cfg.Public[id]; want == nil || !cfg.ECDSA.ActOnBase().Equal(want.ECDSA) {
			t.Errorf("%s: the new share does not match its own public share", id)
		}
		if cfg.Generation != configs[id].Generation+1 {
			t.Errorf("%s: generation %d did not advance from %d", id, cfg.Generation, configs[id].Generation)
		}
		fresh[id] = cfg
	}

	// The shares are new. They must still sign for the SAME key — and the old
	// shares must not be needed to do it.
	msg := sha256.Sum256([]byte("after the reshare"))
	sigs, err := test.RunProtocol(t, ids, []byte("lss-sign-after-reshare"), func(id party.ID) protocol.StartFunc {
		return sign.Start(fresh[id], ids, msg[:], pl)
	})
	if err != nil {
		t.Fatalf("the reshared committee could not sign: %v", err)
	}
	other := sha256.Sum256([]byte("a message nobody signed"))
	for id, res := range sigs {
		sig, ok := res.(*sign.SchnorrSignature)
		if !ok {
			t.Fatalf("%s returned %T, not a signature", id, res)
		}
		if !sig.Verify(publicKey, msg[:]) {
			t.Errorf("%s: a signature from the reshared committee does not verify under the original key", id)
		}
		if sig.Verify(publicKey, other[:]) {
			t.Errorf("%s: that signature also verifies over a message it was never made on", id)
		}
	}
}
