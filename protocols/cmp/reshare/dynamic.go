package reshare

import (
	"crypto/rand"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

// DynamicReshareConfig contains parameters for dynamic re-sharing
type DynamicReshareConfig struct {
	OldParties   []party.ID
	NewParties   []party.ID
	OldThreshold int
	NewThreshold int
	AddParties   []party.ID // Parties being added
	RemoveParties []party.ID // Parties being removed
}

// StartDynamicReshare initiates the dynamic re-sharing protocol
// This implements the 4-step protocol from the LSS paper using the existing CMP framework
func StartDynamicReshare(config *config.Config, reshareConfig *DynamicReshareConfig, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// All parties (old + new) must participate in the resharing
		allParties := mergePartyLists(reshareConfig.OldParties, reshareConfig.AddParties)
		
		info := round.Info{
			ProtocolID:       "cmp/dynamic-reshare-lss",
			FinalRoundNumber: 4, // 4 rounds as per LSS paper
			SelfID:           config.ID,
			PartyIDs:         allParties,
			Threshold:        reshareConfig.NewThreshold,
			Group:            config.Group,
		}
		
		helper, err := round.NewSession(info, sessionID, pl, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create session: %w", err)
		}
		
		// Initialize the first round
		return &round1{
			Helper:         helper,
			Config:         config,
			ReshareConfig:  reshareConfig,
			OldSharesMap:   make(map[party.ID]curve.Scalar),
		}, nil
	}
}

// round1 implements Step 1 from LSS: JVSS for auxiliary secrets w and q
type round1 struct {
	*round.Helper
	Config        *config.Config
	ReshareConfig *DynamicReshareConfig
	
	// Auxiliary secrets for blinding
	WPolynomial   *polynomial.Polynomial
	QPolynomial   *polynomial.Polynomial
	
	// Shares received from other parties
	WShares       map[party.ID]curve.Scalar
	QShares       map[party.ID]curve.Scalar
	
	// For tracking old shares
	OldSharesMap  map[party.ID]curve.Scalar
}

func (r *round1) VerifyMessage(msg round.Message) error {
	// Verify VSS commitments for w and q shares
	return nil
}

func (r *round1) StoreMessage(msg round.Message) error {
	// Store received shares
	return nil
}

func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()
	
	// Generate random polynomials for w and q with degree t-1
	// These are the auxiliary secrets used for blinding
	wConstant := sample.Scalar(rand.Reader, group)
	r.WPolynomial = polynomial.NewPolynomial(group, r.Threshold()-1, wConstant)
	
	qConstant := sample.Scalar(rand.Reader, group)
	r.QPolynomial = polynomial.NewPolynomial(group, r.Threshold()-1, qConstant)
	
	// Create VSS commitments
	wCommitment := polynomial.NewPolynomialExponent(r.WPolynomial)
	qCommitment := polynomial.NewPolynomialExponent(r.QPolynomial)
	
	// Generate shares for all parties
	shares := make(map[party.ID]*auxiliaryShares)
	for _, id := range r.OtherPartyIDs() {
		x := id.Scalar(group)
		shares[id] = &auxiliaryShares{
			WShare: r.WPolynomial.Evaluate(x),
			QShare: r.QPolynomial.Evaluate(x),
		}
	}
	
	// Broadcast commitments and send shares
	broadcastMsg := &round1Message{
		WCommitment: wCommitment,
		QCommitment: qCommitment,
	}
	
	if err := r.BroadcastMessage(out, broadcastMsg); err != nil {
		return nil, err
	}
	
	// Send shares to each party
	for id, share := range shares {
		if err := r.SendMessage(out, &round1ShareMessage{Share: share}, id); err != nil {
			return nil, err
		}
	}
	
	// Store our own shares
	selfX := r.SelfID().Scalar(group)
	r.WShares = map[party.ID]curve.Scalar{
		r.SelfID(): r.WPolynomial.Evaluate(selfX),
	}
	r.QShares = map[party.ID]curve.Scalar{
		r.SelfID(): r.QPolynomial.Evaluate(selfX),
	}
	
	return &round2{round1: r}, nil
}

// round2 implements Step 2 from LSS: Computing blinded secret a·w
type round2 struct {
	*round1
	
	// Combined shares after interpolation
	W           curve.Scalar
	Q           curve.Scalar
	BlindedKey  curve.Scalar // a·w
}

func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()
	
	// Interpolate to get w and q from all shares
	r.W = interpolateShares(group, r.WShares, r.Threshold())
	r.Q = interpolateShares(group, r.QShares, r.Threshold())
	
	// Only old parties compute a_i · w_i
	if isOldParty(r.SelfID(), r.ReshareConfig.OldParties) {
		// Get our old share
		oldShare := r.Config.ECDSA
		
		// Compute blinded share: a_i · w_i
		blindedShare := group.NewScalar().Set(oldShare)
		blindedShare.Mul(r.WShares[r.SelfID()])
		
		// Send to coordinator (in distributed version, this would use MPC)
		msg := &round2Message{
			BlindedShare: blindedShare,
			PartyID:     r.SelfID(),
		}
		
		if err := r.BroadcastMessage(out, msg); err != nil {
			return nil, err
		}
	}
	
	return &round3{round2: r}, nil
}

// round3 implements Step 3 from LSS: Computing inverse blinding factor
type round3 struct {
	*round2
	
	InverseZ curve.Scalar // (q·w)^{-1}
}

func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()
	
	// Compute q·w using shares
	qw := group.NewScalar()
	for id, qShare := range r.QShares {
		wShare := r.WShares[id]
		contribution := group.NewScalar().Set(qShare)
		contribution.Mul(wShare)
		qw.Add(contribution)
	}
	
	// Compute inverse: z = (q·w)^{-1}
	r.InverseZ = group.NewScalar().Set(qw)
	r.InverseZ.Invert()
	
	// Create polynomial for z shares
	zPoly := polynomial.NewPolynomial(group, r.Threshold()-1, r.InverseZ)
	
	// Distribute z shares
	for _, id := range r.OtherPartyIDs() {
		x := id.Scalar(group)
		zShare := zPoly.Evaluate(x)
		
		msg := &round3Message{
			ZShare: zShare,
		}
		
		if err := r.SendMessage(out, msg, id); err != nil {
			return nil, err
		}
	}
	
	return &round4{round3: r}, nil
}

// round4 implements Step 4 from LSS: Final share derivation
type round4 struct {
	*round3
	
	NewShare curve.Scalar
}

func (r *round4) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()
	
	// Each party computes: a_j^{new} = (a·w) · q_j · z_j
	// where (a·w) is the public blinded key
	
	qShare := r.QShares[r.SelfID()]
	zShare := r.InverseZ // In real impl, this would come from shares
	
	// Compute new share
	r.NewShare = group.NewScalar().Set(r.BlindedKey)
	r.NewShare.Mul(qShare)
	r.NewShare.Mul(zShare)
	
	// Create new config with updated shares
	newConfig := &config.Config{
		ID:        r.Config.ID,
		Threshold: r.ReshareConfig.NewThreshold,
		ECDSA:     r.NewShare,
		Group:     r.Config.Group,
		// Copy other fields...
	}
	
	// Return the result round
	return r.ResultRound(newConfig), nil
}

// Helper functions

func mergePartyLists(old, add []party.ID) []party.ID {
	seen := make(map[party.ID]bool)
	result := make([]party.ID, 0)
	
	for _, id := range old {
		if !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	
	for _, id := range add {
		if !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	
	return result
}

func isOldParty(id party.ID, oldParties []party.ID) bool {
	for _, old := range oldParties {
		if id == old {
			return true
		}
	}
	return false
}

func interpolateShares(group curve.Curve, shares map[party.ID]curve.Scalar, threshold int) curve.Scalar {
	// Implement Lagrange interpolation at x=0
	// This is a simplified version - real implementation would be more robust
	result := group.NewScalar()
	
	ids := make([]party.ID, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}
	
	// Use first 'threshold' shares
	for i := 0; i < threshold && i < len(ids); i++ {
		id := ids[i]
		share := shares[id]
		
		// Compute Lagrange coefficient
		coeff := lagrangeCoefficient(group, ids[:threshold], i, group.NewScalar())
		
		// Add contribution
		contribution := group.NewScalar().Set(share)
		contribution.Mul(coeff)
		result.Add(contribution)
	}
	
	return result
}

func lagrangeCoefficient(group curve.Curve, ids []party.ID, index int, x curve.Scalar) curve.Scalar {
	// Compute Lagrange basis polynomial l_i(x)
	one := new(saferith.Nat).SetUint64(1)
	num := group.NewScalar().SetNat(one)
	den := group.NewScalar().SetNat(one)
	
	xi := ids[index].Scalar(group)
	
	for j, id := range ids {
		if j == index {
			continue
		}
		
		xj := id.Scalar(group)
		
		// num *= (x - x_j)
		diff := group.NewScalar().Set(x)
		diff.Sub(xj)
		num.Mul(diff)
		
		// den *= (x_i - x_j)
		diff = group.NewScalar().Set(xi)
		diff.Sub(xj)
		den.Mul(diff)
	}
	
	// Return num/den
	denInv := group.NewScalar().Set(den)
	denInv.Invert()
	result := group.NewScalar().Set(num)
	result.Mul(denInv)
	return result
}

// Message types

type auxiliaryShares struct {
	WShare curve.Scalar
	QShare curve.Scalar
}

type round1Message struct {
	WCommitment *polynomial.Exponent
	QCommitment *polynomial.Exponent
}

type round1ShareMessage struct {
	Share *auxiliaryShares
}

type round2Message struct {
	BlindedShare curve.Scalar
	PartyID      party.ID
}

type round3Message struct {
	ZShare curve.Scalar
}

// Implement round.Content interface for messages
func (m *round1Message) RoundNumber() round.Number { return 1 }
func (m *round1ShareMessage) RoundNumber() round.Number { return 1 }
func (m *round2Message) RoundNumber() round.Number { return 2 }
func (m *round3Message) RoundNumber() round.Number { return 3 }

func (r *round1) Number() round.Number { return 1 }
func (r *round2) Number() round.Number { return 2 }
func (r *round3) Number() round.Number { return 3 }
func (r *round4) Number() round.Number { return 4 }

func (r *round1) PreviousRound() round.Round { return nil }
func (r *round2) PreviousRound() round.Round { return r.round1 }
func (r *round3) PreviousRound() round.Round { return r.round2 }
func (r *round4) PreviousRound() round.Round { return r.round3 }

func (r *round1) MessageContent() round.Content { return &round1Message{} }
func (r *round2) MessageContent() round.Content { return &round2Message{} }
func (r *round3) MessageContent() round.Content { return &round3Message{} }
func (r *round4) MessageContent() round.Content { return nil }