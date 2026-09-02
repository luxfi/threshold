package test

import (
	"io"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// CreateMockLSSConfigs creates mock LSS configs for testing
func CreateMockLSSConfigs(partyIDs []party.ID, threshold int) []*config.Config {
	configs := make([]*config.Config, len(partyIDs))
	group := curve.Secp256k1{}

	for i, id := range partyIDs {
		configs[i] = &config.Config{
			ID:        id,
			Threshold: threshold,
			Group:     group,
			ECDSA:     group.NewScalar(),
			ChainKey:  []byte("mock-chain-key"),
			RID:       []byte("mock-rid"),
			Public:    make(map[party.ID]*config.Public),
		}

		// Add public keys for all parties
		for _, pid := range partyIDs {
			configs[i].Public[pid] = &config.Public{
				ECDSA: group.NewPoint(),
			}
		}
	}

	return configs
}

// CreateMockFROSTConfigs creates mock FROST configs for testing
func CreateMockFROSTConfigs(partyIDs []party.ID, threshold int) []interface{} {
	configs := make([]interface{}, len(partyIDs))
	group := curve.Secp256k1{}

	for i, id := range partyIDs {
		// Create a mock config that satisfies FROST requirements
		configs[i] = struct {
			ID           party.ID
			Threshold    int
			Group        curve.Curve
			PublicKey    curve.Point
			SecretShare  curve.Scalar
			PublicShares map[party.ID]curve.Point
		}{
			ID:           id,
			Threshold:    threshold,
			Group:        group,
			PublicKey:    group.NewPoint(),
			SecretShare:  group.NewScalar(),
			PublicShares: make(map[party.ID]curve.Point),
		}
	}

	return configs
}

// CreateMockCMPConfigs creates mock CMP configs for testing
func CreateMockCMPConfigs(partyIDs []party.ID, threshold int) []interface{} {
	configs := make([]interface{}, len(partyIDs))
	group := curve.Secp256k1{}

	for i, id := range partyIDs {
		// Create a mock config that satisfies CMP requirements
		configs[i] = struct {
			ID        party.ID
			Threshold int
			Group     curve.Curve
			PublicKey curve.Point
			Share     curve.Scalar
			Nonce     []byte
		}{
			ID:        id,
			Threshold: threshold,
			Group:     group,
			PublicKey: group.NewPoint(),
			Share:     group.NewScalar(),
			Nonce:     []byte("mock-nonce"),
		}
	}

	return configs
}

// SharedLSSConfigs builds a REAL Shamir sharing of one key over ids: each
// config's ECDSA is f(id), every party's Public holds f(j)·G, and those
// interpolate back to f(0)·G, which is what PublicPoint expects and what a
// signature verifies against. It returns the group public key alongside.
//
// CreateMockLSSConfigs above cannot stand in for this. Its shares are the zero
// scalar and its public points are the identity, so a protocol run over it
// proves nothing about signing — which is how a whole package of round code
// stayed at zero coverage behind tests that looked like they exercised it.
func SharedLSSConfigs(ids []party.ID, degree int, rand io.Reader) (map[party.ID]*config.Config, curve.Point) {
	group := curve.Secp256k1{}
	secret := sample.Scalar(rand, group)
	poly := polynomial.NewPolynomial(group, degree, secret)

	public := make(map[party.ID]*config.Public, len(ids))
	shares := make(map[party.ID]curve.Scalar, len(ids))
	for _, id := range ids {
		s := poly.Evaluate(id.Scalar(group))
		shares[id] = s
		public[id] = &config.Public{ECDSA: s.ActOnBase()}
	}

	configs := make(map[party.ID]*config.Config, len(ids))
	for _, id := range ids {
		configs[id] = &config.Config{
			ID:        id,
			Group:     group,
			Threshold: degree + 1,
			ECDSA:     shares[id],
			Public:    public,
			ChainKey:  []byte("chain-key"),
			RID:       []byte("rid"),
		}
	}
	return configs, secret.ActOnBase()
}
