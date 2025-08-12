package keygen

import (
	"crypto/rand"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/paillier"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pedersen"
	"github.com/luxfi/threshold/pkg/protocol"
	zksch "github.com/luxfi/threshold/pkg/zk/sch"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	// PreviousSecretECDSA = sk'ᵢ
	// Contains the previous secret ECDSA key share which is being refreshed
	// Keygen:  sk'ᵢ = nil
	// Refresh: sk'ᵢ = sk'ᵢ
	PreviousSecretECDSA curve.Scalar

	// PreviousPublicSharesECDSA[j] = pk'ⱼ
	// Keygen:  pk'ⱼ = nil
	// Refresh: pk'ⱼ = pk'ⱼ
	PreviousPublicSharesECDSA map[party.ID]curve.Point

	// PreviousChainKey contains the chain key, if we're refreshing
	//
	// In that case, we will simply use the previous chain key at the very end.
	PreviousChainKey types.RID

	// VSSSecret = fᵢ(X)
	// Polynomial from which the new secret shares are computed.
	// Keygen:  fᵢ(0) = xⁱ
	// Refresh: fᵢ(0) = 0
	VSSSecret *polynomial.Polynomial

	// keyID is the stable cross-phase identifier for this key generation context
	keyID *protocol.KeyID
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - sample Paillier (pᵢ, qᵢ)
// - sample Pedersen Nᵢ, sᵢ, tᵢ
// - sample aᵢ  <- 𝔽
// - set Aᵢ = aᵢ⋅G
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample ridᵢ <- {0,1}ᵏ
// - sample cᵢ <- {0,1}ᵏ
// - commit to message.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// generate Paillier and Pedersen
	PaillierSecret := paillier.NewSecretKey(nil)
	SelfPaillierPublic := PaillierSecret.PublicKey
	SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()

	ElGamalSecret, ElGamalPublic := sample.ScalarPointPair(rand.Reader, r.Group())

	// save our own share already so we are consistent with what we receive from others
	SelfShare := r.VSSSecret.Evaluate(r.SelfID().Scalar(r.Group()))

	// set Fᵢ(X) = fᵢ(X)•G
	SelfVSSPolynomial := polynomial.NewPolynomialExponent(r.VSSSecret)

	// generate Schnorr randomness
	SchnorrRand := zksch.NewRandomness(rand.Reader, r.Group(), nil)

	// Sample RIDᵢ
	SelfRID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample Rho")
	}
	chainKey, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample c")
	}

	// commit to data in message 2
	// Use KeyID for stable cross-phase commitments instead of sessionID-based hash
	SelfCommitment, Decommitment, err := r.keyID.HashForParty(r.SelfID()).Commit(
		SelfRID, chainKey, SelfVSSPolynomial, SchnorrRand.Commitment(), ElGamalPublic,
		SelfPedersenPublic.N(), SelfPedersenPublic.S(), SelfPedersenPublic.T())
	if err != nil {
		return r, errors.New("failed to commit")
	}

	// should be broadcast but we don't need that here
	msg := &broadcast2{Commitment: SelfCommitment}
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}

	nextRound := &round2{
		round1:         r,
		VSSPolynomials: map[party.ID]*polynomial.Exponent{r.SelfID(): SelfVSSPolynomial},
		Commitments:    map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		RIDs:           map[party.ID]types.RID{r.SelfID(): SelfRID},
		ChainKeys:      map[party.ID]types.RID{r.SelfID(): chainKey},
		ShareReceived:  map[party.ID]curve.Scalar{r.SelfID(): SelfShare},
		ElGamalPublic:  map[party.ID]curve.Point{r.SelfID(): ElGamalPublic},
		PaillierPublic: map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
		Pedersen:       map[party.ID]*pedersen.Parameters{r.SelfID(): SelfPedersenPublic},
		ElGamalSecret:  ElGamalSecret,
		PaillierSecret: PaillierSecret,
		PedersenSecret: PedersenSecret,
		SchnorrRand:    SchnorrRand,
		Decommitment:   Decommitment,
	}
	return nextRound, nil
}

// PreviousRound implements round.Round.
func (round1) PreviousRound() round.Round { return nil }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }

// BroadcastContent implements round.BroadcastRound.
// Note: Round1 sends broadcast2 messages in Finalize but must implement 
// BroadcastContent to avoid the handler thinking no broadcasts are expected
// and finalizing immediately (handler.go line 364-365).
func (round1) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// StoreBroadcastMessage implements round.BroadcastRound.
// Round1 doesn't receive broadcasts, but must implement this to satisfy the interface.
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	// Round1 doesn't receive broadcasts
	return nil
}
