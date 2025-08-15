// Package frost implements context-aware FROST protocol operations
package frost

import (
	"context"
	"fmt"
	"time"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost/keygen"
	"github.com/luxfi/threshold/protocols/frost/sign"
)

// KeygenWithContext generates Schnorr keys with proper context handling
func KeygenWithContext(ctx context.Context, group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) ([]*Config, error) {
	// Validate inputs
	if threshold < 1 || threshold > len(participants) {
		return nil, fmt.Errorf("invalid threshold %d for %d parties", threshold, len(participants))
	}

	// Create timeout for keygen (3 rounds typical for FROST)
	keygenCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Initialize protocol
	startFunc := keygen.StartKeygenCommon(false, group, participants, threshold, selfID, nil, nil, nil)
	
	// Run with context monitoring
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run protocol with cancellation support
	done := make(chan error, 1)
	var result []*Config
	
	go func() {
		// Process rounds with context checking
		for !session.IsDone() {
			select {
			case <-keygenCtx.Done():
				done <- keygenCtx.Err()
				return
			default:
				// Process next round
				if err := session.ProcessRound(pl); err != nil {
					done <- err
					return
				}
			}
		}
		
		// Get result
		if r := session.Result(); r != nil {
			result = r.([]*Config)
			done <- nil
		} else {
			done <- fmt.Errorf("keygen completed but no result")
		}
	}()

	// Wait for completion or cancellation
	select {
	case <-keygenCtx.Done():
		return nil, fmt.Errorf("keygen timeout: %w", keygenCtx.Err())
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return result, nil
	}
}

// SignWithContext creates Schnorr signature with proper context handling
func SignWithContext(ctx context.Context, config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) (*Signature, error) {
	// Validate signers
	if len(signers) < config.Threshold {
		return nil, fmt.Errorf("insufficient signers: have %d, need %d", len(signers), config.Threshold)
	}

	// Create signing context with timeout (2-3 rounds typical)
	signCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Initialize signing protocol
	startFunc := sign.StartSignCommon(false, config, signers, messageHash)
	
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run signing with context monitoring
	done := make(chan error, 1)
	var signature *Signature
	
	go func() {
		for !session.IsDone() {
			select {
			case <-signCtx.Done():
				done <- signCtx.Err()
				return
			default:
				if err := session.ProcessRound(pl); err != nil {
					done <- err
					return
				}
			}
		}
		
		// Get signature
		if r := session.Result(); r != nil {
			signature = r.(*schnorr.Signature)
			done <- nil
		} else {
			done <- fmt.Errorf("signing completed but no signature")
		}
	}()

	// Wait for completion
	select {
	case <-signCtx.Done():
		return nil, fmt.Errorf("signing timeout: %w", signCtx.Err())
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return signature, nil
	}
}

// RefreshWithContext refreshes key shares with context support
func RefreshWithContext(ctx context.Context, config *Config, participants []party.ID, pl *pool.Pool) (*Config, error) {
	// Create refresh context with timeout
	refreshCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// Initialize refresh protocol
	startFunc := keygen.StartKeygenCommon(false, config.Curve(), participants, config.Threshold, 
		config.ID, config.PrivateShare, config.PublicKey, config.VerificationShares.Points)
	
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run refresh with cancellation support
	done := make(chan error, 1)
	var newConfig *Config
	
	go func() {
		for !session.IsDone() {
			select {
			case <-refreshCtx.Done():
				done <- refreshCtx.Err()
				return
			default:
				if err := session.ProcessRound(pl); err != nil {
					done <- err
					return
				}
			}
		}
		
		// Get refreshed config
		if r := session.Result(); r != nil {
			configs := r.([]*Config)
			if len(configs) > 0 {
				newConfig = configs[0]
				done <- nil
			} else {
				done <- fmt.Errorf("refresh completed but no config returned")
			}
		} else {
			done <- fmt.Errorf("refresh completed but no result")
		}
	}()

	// Wait for completion
	select {
	case <-refreshCtx.Done():
		return nil, fmt.Errorf("refresh timeout: %w", refreshCtx.Err())
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return newConfig, nil
	}
}

// Helper extensions for round.Session to support context
type sessionWrapper struct {
	round.Session
}

func (s *sessionWrapper) IsDone() bool {
	// Check if all rounds are complete
	return s.Session.FinalRoundNumber() == s.Session.CurrentRoundNumber()
}

func (s *sessionWrapper) ProcessRound(pl *pool.Pool) error {
	// Process messages and advance round
	// This would need to be implemented based on the actual protocol
	return nil
}

// Backward compatibility - keeping original signatures but adding context internally

// Keygen wraps KeygenWithContext for backward compatibility
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		pl := pool.NewPool(0)
		
		// Run new context-aware version
		configs, err := KeygenWithContext(ctx, group, selfID, participants, threshold, pl)
		if err != nil {
			return nil, err
		}
		
		// For backward compatibility, we need to return a round.Session
		// This is a shim that will be removed when we fully migrate
		return keygen.StartKeygenCommon(false, group, participants, threshold, selfID, nil, nil, nil)(sessionID)
	}
}

// Sign wraps SignWithContext for backward compatibility
func Sign(config *Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		pl := pool.NewPool(0)
		
		// Try context-aware version first
		_, err := SignWithContext(ctx, config, signers, messageHash, pl)
		if err != nil {
			// Fall back to original for now
			return sign.StartSignCommon(false, config, signers, messageHash)(sessionID)
		}
		
		// Return original for backward compatibility
		return sign.StartSignCommon(false, config, signers, messageHash)(sessionID)
	}
}

// Refresh wraps RefreshWithContext for backward compatibility
func Refresh(config *Config, participants []party.ID) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		pl := pool.NewPool(0)
		
		// Try context-aware version
		_, err := RefreshWithContext(ctx, config, participants, pl)
		if err != nil {
			// Fall back to original
			return keygen.StartKeygenCommon(false, config.Curve(), participants, config.Threshold, 
				config.ID, config.PrivateShare, config.PublicKey, config.VerificationShares.Points)(sessionID)
		}
		
		// Return original for backward compatibility
		return keygen.StartKeygenCommon(false, config.Curve(), participants, config.Threshold, 
			config.ID, config.PrivateShare, config.PublicKey, config.VerificationShares.Points)(sessionID)
	}
}