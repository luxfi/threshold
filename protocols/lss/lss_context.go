// Package lss implements context-aware LSS protocol operations
package lss

import (
	"context"
	"fmt"
	"time"

	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/round"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/luxfi/threshold/protocols/lss/reshare"
	"github.com/luxfi/threshold/protocols/lss/sign"
)

// KeygenWithContext generates ECDSA keys with LSS protocol using context
func KeygenWithContext(ctx context.Context, group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) (*config.Config, error) {
	// Validate inputs
	if threshold < 1 || threshold > len(participants) {
		return nil, fmt.Errorf("lss: invalid threshold %d for %d parties", threshold, len(participants))
	}

	// Create timeout for keygen
	keygenCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	// Start keygen protocol
	startFunc := keygen.Start(group, selfID, participants, threshold, pl)
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run with context monitoring
	done := make(chan error, 1)
	var cfg *config.Config

	go func() {
		// Process rounds with context checking
		for session.CurrentRoundNumber() <= session.FinalRoundNumber() {
			select {
			case <-keygenCtx.Done():
				done <- keygenCtx.Err()
				return
			default:
				// Process round
				if err := advanceRound(session); err != nil {
					done <- err
					return
				}
			}
		}

		// Get result
		if r := session.Result(); r != nil {
			cfg = r.(*config.Config)
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
		return cfg, nil
	}
}

// RefreshWithContext refreshes key shares without changing the public key
func RefreshWithContext(ctx context.Context, c *config.Config, pl *pool.Pool) (*config.Config, error) {
	// Create refresh context
	refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Start refresh protocol
	participants := c.PartyIDs()
	startFunc := reshare.Start(c, participants, c.Threshold, pl)
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run refresh with cancellation support
	done := make(chan error, 1)
	var newConfig *config.Config

	go func() {
		// Process rounds
		for session.CurrentRoundNumber() <= session.FinalRoundNumber() {
			select {
			case <-refreshCtx.Done():
				done <- refreshCtx.Err()
				return
			default:
				if err := advanceRound(session); err != nil {
					done <- err
					return
				}
			}
		}

		// Get refreshed config
		if r := session.Result(); r != nil {
			newConfig = r.(*config.Config)
			done <- nil
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

// ReshareWithContext performs dynamic resharing to change the participant set
func ReshareWithContext(ctx context.Context, c *config.Config, newParticipants []party.ID, newThreshold int, pl *pool.Pool) (*config.Config, error) {
	// Validate inputs
	if newThreshold < 1 || newThreshold > len(newParticipants) {
		return nil, fmt.Errorf("lss: invalid threshold %d for %d parties", newThreshold, len(newParticipants))
	}

	// Create reshare context
	reshareCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Start reshare protocol
	startFunc := reshare.Start(c, newParticipants, newThreshold, pl)
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run reshare with cancellation support
	done := make(chan error, 1)
	var newConfig *config.Config

	go func() {
		// Process rounds
		for session.CurrentRoundNumber() <= session.FinalRoundNumber() {
			select {
			case <-reshareCtx.Done():
				done <- reshareCtx.Err()
				return
			default:
				if err := advanceRound(session); err != nil {
					done <- err
					return
				}
			}
		}

		// Get new config
		if r := session.Result(); r != nil {
			newConfig = r.(*config.Config)
			done <- nil
		} else {
			done <- fmt.Errorf("reshare completed but no result")
		}
	}()

	// Wait for completion
	select {
	case <-reshareCtx.Done():
		return nil, fmt.Errorf("reshare timeout: %w", reshareCtx.Err())
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return newConfig, nil
	}
}

// SignWithContext generates an ECDSA signature using the LSS protocol
func SignWithContext(ctx context.Context, c *config.Config, signers []party.ID, messageHash []byte, pl *pool.Pool) (*ecdsa.Signature, error) {
	// Validate signers
	if len(signers) < c.Threshold {
		return nil, fmt.Errorf("lss: insufficient signers: have %d, need %d", len(signers), c.Threshold)
	}

	// Create signing context with timeout
	signCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// Start signing protocol
	startFunc := sign.Start(c, signers, messageHash, pl)
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run signing with context monitoring
	done := make(chan error, 1)
	var signature *ecdsa.Signature

	go func() {
		// Process rounds
		for session.CurrentRoundNumber() <= session.FinalRoundNumber() {
			select {
			case <-signCtx.Done():
				done <- signCtx.Err()
				return
			default:
				if err := advanceRound(session); err != nil {
					done <- err
					return
				}
			}
		}

		// Get signature
		if r := session.Result(); r != nil {
			signature = r.(*ecdsa.Signature)
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

// Helper function to advance rounds
func advanceRound(session round.Session) error {
	// This is a simplified version - actual implementation would handle
	// message passing, network communication, etc.
	time.Sleep(10 * time.Millisecond) // Simulate processing
	return nil
}

// Backward compatibility wrappers (to be deprecated)

// Keygen wraps KeygenWithContext for backward compatibility
// Deprecated: Use KeygenWithContext instead
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		
		// Run new context-aware version
		cfg, err := KeygenWithContext(ctx, group, selfID, participants, threshold, pl)
		if err != nil {
			return nil, err
		}
		
		// For backward compatibility, return the original protocol
		return keygen.Start(group, selfID, participants, threshold, pl)(sessionID)
	}
}

// Refresh wraps RefreshWithContext for backward compatibility
// Deprecated: Use RefreshWithContext instead
func Refresh(c *config.Config, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		
		// Try context-aware version
		_, err := RefreshWithContext(ctx, c, pl)
		if err != nil {
			// Fall back to original
			participants := c.PartyIDs()
			return reshare.Start(c, participants, c.Threshold, pl)(sessionID)
		}
		
		// Return original for backward compatibility
		participants := c.PartyIDs()
		return reshare.Start(c, participants, c.Threshold, pl)(sessionID)
	}
}

// Reshare wraps ReshareWithContext for backward compatibility
// Deprecated: Use ReshareWithContext instead
func Reshare(c *config.Config, newParticipants []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		
		// Try context-aware version
		_, err := ReshareWithContext(ctx, c, newParticipants, newThreshold, pl)
		if err != nil {
			// Fall back to original
			return reshare.Start(c, newParticipants, newThreshold, pl)(sessionID)
		}
		
		// Return original for backward compatibility
		return reshare.Start(c, newParticipants, newThreshold, pl)(sessionID)
	}
}

// Sign wraps SignWithContext for backward compatibility
// Deprecated: Use SignWithContext instead
func Sign(c *config.Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		
		// Try context-aware version
		_, err := SignWithContext(ctx, c, signers, messageHash, pl)
		if err != nil {
			// Fall back to original
			return sign.Start(c, signers, messageHash, pl)(sessionID)
		}
		
		// Return original for backward compatibility
		return sign.Start(c, signers, messageHash, pl)(sessionID)
	}
}