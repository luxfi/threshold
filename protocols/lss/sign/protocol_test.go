package sign_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/sign"
)

// THE PROTOCOL, RUN. Every round in this package was at zero coverage: the
// tests built a session and asserted it was non-nil, so no Finalize, no
// VerifyMessage and no StoreMessage ever executed. That is how a challenge
// which did not cover the message survived — the signature it produced was
// never checked against anything.
func TestTheProtocolProducesASignatureOverItsMessage(t *testing.T) {
	ids := []party.ID{"alice", "bob", "charlie"}
	configs, publicKey := test.SharedLSSConfigs(ids, 1, rand.Reader) // degree 1: any two of three sign

	msg := sha256.Sum256([]byte("send alice one coin"))
	pl := pool.NewPool(0)
	defer pl.TearDown()

	results, err := test.RunProtocol(t, ids, []byte("lss-sign-session"), func(id party.ID) protocol.StartFunc {
		return sign.Start(configs[id], ids, msg[:], pl)
	})
	if err != nil {
		t.Fatalf("the signing protocol did not complete: %v", err)
	}

	other := sha256.Sum256([]byte("send bob one thousand coins"))
	for id, res := range results {
		sig, ok := res.(*sign.SchnorrSignature)
		if !ok {
			t.Fatalf("%s returned %T, not a signature", id, res)
		}
		if !sig.Verify(publicKey, msg[:]) {
			t.Errorf("%s: the signature does not verify over the message it was made on", id)
		}
		if sig.Verify(publicKey, other[:]) {
			t.Errorf("%s: the signature verifies over a message it was never made on", id)
		}
	}
}
