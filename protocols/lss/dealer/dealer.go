package dealer

import (
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss"
)

// BootstrapDealer implements the dealer role for LSS dynamic re-sharing
type BootstrapDealer struct {
	mu sync.RWMutex

	// Current network state
	currentGeneration uint64
	currentThreshold  int
	currentParties    []party.ID

	// Re-sharing protocol state
	reshareInProgress bool
	newThreshold      int
	newParties        []party.ID

	// Auxiliary secrets for re-sharing
	wShares map[party.ID]curve.Scalar // Shares of blinding factor w
	qShares map[party.ID]curve.Scalar // Shares of auxiliary secret q

	// Blinded products collected during re-sharing
	blindedProducts   map[party.ID]curve.Scalar
	qwProducts        map[party.ID]curve.Scalar
	verificationCount map[party.ID]bool

	// Computed values during resharing
	blindedSecret curve.Scalar // a * w
	inverseZ      curve.Scalar // (q * w)^{-1}

	// Communication channels
	broadcastChan chan *lss.ReshareMessage

	group curve.Curve
}

// NewBootstrapDealer creates a new Bootstrap Dealer instance
func NewBootstrapDealer(group curve.Curve, initialParties []party.ID, threshold int) *BootstrapDealer {
	return &BootstrapDealer{
		currentGeneration: 0,
		currentThreshold:  threshold,
		currentParties:    initialParties,
		group:             group,
		wShares:           make(map[party.ID]curve.Scalar),
		qShares:           make(map[party.ID]curve.Scalar),
		blindedProducts:   make(map[party.ID]curve.Scalar),
		qwProducts:        make(map[party.ID]curve.Scalar),
		broadcastChan:     make(chan *lss.ReshareMessage, 100),
	}
}

// InitiateReshare starts a new re-sharing protocol as described in Section 4 of the LSS paper
func (d *BootstrapDealer) InitiateReshare(_ int, newThreshold int, addParties, removeParties []party.ID) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.reshareInProgress {
		return errors.New("re-share already in progress")
	}

	// Validate parameters
	if newThreshold < 1 {
		return errors.New("invalid threshold")
	}

	// Calculate new party set
	newPartySet := make(map[party.ID]bool)
	for _, p := range d.currentParties {
		newPartySet[p] = true
	}
	for _, p := range removeParties {
		delete(newPartySet, p)
	}
	for _, p := range addParties {
		newPartySet[p] = true
	}

	d.newParties = make([]party.ID, 0, len(newPartySet))
	for p := range newPartySet {
		d.newParties = append(d.newParties, p)
	}

	if newThreshold > len(d.newParties) {
		return fmt.Errorf("threshold %d exceeds party count %d", newThreshold, len(d.newParties))
	}

	d.reshareInProgress = true
	d.newThreshold = newThreshold

	// Step 1: Initiate JVSS for auxiliary secrets w and q
	// This follows Section 4, Step 1 of the paper
	go d.runJVSSProtocol()

	return nil
}

// runJVSSProtocol coordinates the JVSS process for generating auxiliary secrets
func (d *BootstrapDealer) runJVSSProtocol() {
	// Generate random polynomials for w and q
	wPoly := polynomial.NewPolynomial(d.group, d.newThreshold-1, nil)
	qPoly := polynomial.NewPolynomial(d.group, d.newThreshold-1, nil)

	// Create shares for each party
	for _, partyID := range d.newParties {
		d.wShares[partyID] = wPoly.Evaluate(partyID.Scalar(d.group))
		d.qShares[partyID] = qPoly.Evaluate(partyID.Scalar(d.group))
	}

	// Broadcast commitment phase message
	msg := &lss.ReshareMessage{
		Type:       lss.ReshareTypeJVSSCommitment,
		Generation: d.currentGeneration + 1,
		// In practice, we'd serialize commitments here
	}

	d.broadcastChan <- msg
}

// HandleReshareMessage processes incoming re-share protocol messages
func (d *BootstrapDealer) HandleReshareMessage(from party.ID, msg *lss.ReshareMessage) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.reshareInProgress {
		return errors.New("no re-share in progress")
	}

	switch msg.Type {
	case lss.ReshareTypeJVSSCommitment:
		// Handle JVSS commitment messages
		return errors.New("JVSS commitment handling not yet implemented")

	case lss.ReshareTypeBlindedShare:
		// Step 2: Collect blinded products a_i * w_i from original parties
		// The dealer interpolates these to get a * w
		return d.handleBlindedShare(from, msg)

	case lss.ReshareTypeBlindedProduct:
		// Step 3: Collect blinded products q_j * w_j from all parties
		// The dealer interpolates these to get q * w, then computes z = (q * w)^{-1}
		return d.handleBlindedProduct(from, msg)

	case lss.ReshareTypeVerification:
		// Final verification that new shares are correct
		return d.handleVerification(from, msg)

	default:
		return fmt.Errorf("unexpected message type: %v", msg.Type)
	}
}

func (d *BootstrapDealer) handleBlindedShare(from party.ID, msg *lss.ReshareMessage) error {
	// Deserialize the blinded share a_i * w_i
	if len(msg.Data) == 0 {
		return errors.New("empty blinded share data")
	}

	// Parse the scalar from message data
	blindedShare := d.group.NewScalar()
	if err := blindedShare.UnmarshalBinary(msg.Data); err != nil {
		return fmt.Errorf("failed to unmarshal blinded share: %w", err)
	}

	// Store the blinded product
	d.blindedProducts[from] = blindedShare

	// Check if we have enough shares to interpolate
	if len(d.blindedProducts) >= d.currentThreshold {
		// Get the party IDs that contributed
		contributingParties := make([]party.ID, 0, len(d.blindedProducts))
		for pid := range d.blindedProducts {
			contributingParties = append(contributingParties, pid)
		}

		// Compute Lagrange coefficients
		lagrange := polynomial.Lagrange(d.group, contributingParties[:d.currentThreshold])

		// Interpolate to get a * w
		aTimesW := d.group.NewScalar()
		for _, pid := range contributingParties[:d.currentThreshold] {
			share := d.blindedProducts[pid]
			if coeff, exists := lagrange[pid]; exists {
				contribution := d.group.NewScalar().Set(coeff).Mul(share)
				aTimesW.Add(contribution)
			}
		}

		// Store the blinded secret for later use
		d.mu.Lock()
		d.blindedSecret = aTimesW
		d.mu.Unlock()

		// Move to next phase
		d.initiateInverseComputation()
	}

	return nil
}

func (d *BootstrapDealer) handleBlindedProduct(from party.ID, msg *lss.ReshareMessage) error {
	// Deserialize the q_j * w_j product
	if len(msg.Data) == 0 {
		return errors.New("empty blinded product data")
	}

	qwProduct := d.group.NewScalar()
	if err := qwProduct.UnmarshalBinary(msg.Data); err != nil {
		return fmt.Errorf("failed to unmarshal blinded product: %w", err)
	}

	// Store the product
	d.qwProducts[from] = qwProduct

	// Check if we have enough products to interpolate
	if len(d.qwProducts) >= d.newThreshold {
		// Get contributing parties
		contributingParties := make([]party.ID, 0, len(d.qwProducts))
		for pid := range d.qwProducts {
			contributingParties = append(contributingParties, pid)
			if len(contributingParties) >= d.newThreshold {
				break
			}
		}

		// Compute Lagrange coefficients
		lagrange := polynomial.Lagrange(d.group, contributingParties)

		// Interpolate to get q * w
		qTimesW := d.group.NewScalar()
		for _, pid := range contributingParties {
			product := d.qwProducts[pid]
			if coeff, exists := lagrange[pid]; exists {
				contribution := d.group.NewScalar().Set(coeff).Mul(product)
				qTimesW.Add(contribution)
			}
		}

		// Compute z = (q * w)^{-1}
		d.inverseZ = qTimesW.Invert()

		// Create shares of z for distribution
		zPoly := polynomial.NewPolynomial(d.group, d.newThreshold-1, d.inverseZ)
		
		// Distribute z shares to new parties
		for _, partyID := range d.newParties {
			zShare := zPoly.Evaluate(partyID.Scalar(d.group))
			
			// Serialize and send z share
			zShareData, err := zShare.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal z share: %w", err)
			}

			msg := &lss.ReshareMessage{
				Type:       lss.ReshareTypeVerification,
				Generation: d.currentGeneration + 1,
				Data:       zShareData,
			}
			
			d.broadcastChan <- msg
		}
	}

	return nil
}

func (d *BootstrapDealer) handleVerification(from party.ID, msg *lss.ReshareMessage) error {
	// This message contains verification data from parties
	// confirming they have valid new shares
	
	if len(msg.Data) == 0 {
		return errors.New("empty verification data")
	}
	
	// In a complete implementation, parties would send:
	// 1. Proof that their new share is valid
	// 2. Commitment to their new public share
	// 3. Verification that they can participate in signing
	
	// For now, we'll just track that we received verification
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Count verifications received
	if d.verificationCount == nil {
		d.verificationCount = make(map[party.ID]bool)
	}
	d.verificationCount[from] = true
	
	// Check if we have enough verifications
	if len(d.verificationCount) >= d.newThreshold {
		// Resharing is considered successful
		// Parties can now use their new shares
		return d.CompleteReshare()
	}
	
	return nil
}

func (d *BootstrapDealer) initiateInverseComputation() {
	// Step 3 of the protocol: compute inverse of q * w
	// Then create and distribute shares of z = (q * w)^{-1}

	// This follows Section 4, Step 3 of the paper
}

// GetCurrentGeneration returns the current shard generation
func (d *BootstrapDealer) GetCurrentGeneration() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.currentGeneration
}

// CompleteReshare finalizes the re-sharing protocol
func (d *BootstrapDealer) CompleteReshare() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.reshareInProgress {
		return errors.New("no re-share in progress")
	}

	// Update state
	d.currentGeneration++
	d.currentThreshold = d.newThreshold
	d.currentParties = d.newParties
	d.reshareInProgress = false

	// Clear temporary state
	d.wShares = make(map[party.ID]curve.Scalar)
	d.qShares = make(map[party.ID]curve.Scalar)
	d.blindedProducts = make(map[party.ID]curve.Scalar)
	d.qwProducts = make(map[party.ID]curve.Scalar)
	d.verificationCount = make(map[party.ID]bool)

	return nil
}
