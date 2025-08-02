package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

const Rounds round.Number = 5

func Start(info round.Info, pl *pool.Pool, c *config.Config) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		var helper *round.Helper
		if c == nil {
			helper, err = round.NewSession(info, sessionID, pl)
		} else {
			helper, err = round.NewSession(info, sessionID, pl, c)
		}
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		group := helper.Group()

		if c != nil {
			PublicSharesECDSA := make(map[party.ID]curve.Point, len(c.Public))
			for id, public := range c.Public {
				PublicSharesECDSA[id] = public.ECDSA
			}
			return &round1{
				Helper:                    helper,
				PreviousSecretECDSA:       c.ECDSA,
				PreviousPublicSharesECDSA: PublicSharesECDSA,
				PreviousChainKey:          c.ChainKey,
				VSSSecret:                 polynomial.NewPolynomial(group, helper.Threshold(), group.NewScalar()), // fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
			}, nil
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		VSSConstant := sample.Scalar(rand.Reader, group)
		VSSSecret := polynomial.NewPolynomial(group, helper.Threshold(), VSSConstant)
		return &round1{
			Helper:    helper,
			VSSSecret: VSSSecret,
		}, nil

	}
}
