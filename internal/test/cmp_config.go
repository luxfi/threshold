package test

import (
	"io"

	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/paillier"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pedersen"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

// GenerateConfig creates some random configuration for N parties with set threshold T over the group.
func GenerateConfig(group curve.Curve, N, T int, source io.Reader, pl *pool.Pool) (map[party.ID]*config.Config, party.IDSlice) {
	partyIDs := PartyIDs(N)
	configs := make(map[party.ID]*config.Config, N)
	public := make(map[party.ID]*config.Public, N)

	f := polynomial.NewPolynomial(group, T, sample.Scalar(source, group))

	rid, err := types.NewRID(source)
	if err != nil {
		panic(err)
	}
	chainKey, err := types.NewRID(source)
	if err != nil {
		panic(err)
	}

	for _, pid := range partyIDs {
		paillierSecret := paillier.NewSecretKey(pl)
		s, t, _ := sample.Pedersen(source, paillierSecret.Phi(), paillierSecret.N())
		pedersenPublic := pedersen.New(paillierSecret.Modulus(), s, t)
		elGamalSecret := sample.Scalar(source, group)

		ecdsaSecret := f.Evaluate(pid.Scalar(group))
		configs[pid] = &config.Config{
			Group:     group,
			ID:        pid,
			Threshold: T,
			ECDSA:     ecdsaSecret,
			ElGamal:   elGamalSecret,
			Paillier:  paillierSecret,
			RID:       rid.Copy(),
			ChainKey:  chainKey.Copy(),
			Public:    public,
		}
		X := ecdsaSecret.ActOnBase()
		public[pid] = &config.Public{
			ECDSA:    X,
			ElGamal:  elGamalSecret.ActOnBase(),
			Paillier: paillierSecret.PublicKey,
			Pedersen: pedersenPublic,
		}
	}
	return configs, partyIDs
}
