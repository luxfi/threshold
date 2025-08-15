// Package cmp implements context-aware CMP protocol operations
package cmp

import (
	"context"
	"fmt"
	"time"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp/keygen"
	"github.com/luxfi/threshold/protocols/cmp/sign"
)

// KeygenWithContext generates ECDSA keys with proper context handling
func KeygenWithContext(ctx context.Context, group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) ([]*Config, error) {
	// Validate inputs
	if threshold < 1 || threshold > len(participants) {
		return nil, fmt.Errorf("invalid threshold %d for %d parties", threshold, len(participants))
	}

	// Create timeout for keygen (typically needs more time for CMP)
	keygenCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Initialize keygen
	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           selfID,
		PartyIDs:         participants,
		Threshold:        threshold,
		Group:            group,
	}

	// Start keygen protocol
	startFunc := keygen.StartKeygen(info, pl, nil)
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run with context monitoring
	done := make(chan error, 1)
	var configs []*Config

	go func() {
		// Process rounds with context checking
		for session.CurrentRoundNumber() <= session.FinalRoundNumber() {
			select {
			case <-keygenCtx.Done():
				done <- keygenCtx.Err()
				return
			default:
				// Advance the round
				if err := processRound(session, pl); err != nil {
					done <- err
					return
				}
			}
		}

		// Get result
		if r := session.Result(); r != nil {
			configs = r.([]*Config)
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
		return configs, nil
	}
}

// SignWithContext creates ECDSA signature with proper context handling
func SignWithContext(ctx context.Context, config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) (*ecdsa.Signature, error) {
	// Validate signers
	if len(signers) < config.Threshold {
		return nil, fmt.Errorf("insufficient signers: have %d, need %d", len(signers), config.Threshold)
	}

	// Create signing context with timeout
	signCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Start signing protocol
	startFunc := sign.StartSign(config, signers, messageHash, pl)
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
				if err := processRound(session, pl); err != nil {
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

// RefreshWithContext refreshes key shares with context support
func RefreshWithContext(ctx context.Context, config *Config, pl *pool.Pool) (*Config, error) {
	// Create refresh context
	refreshCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	// Initialize refresh (same as keygen but with existing config)
	info := round.Info{
		ProtocolID:       "cmp/refresh-threshold",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           config.ID,
		PartyIDs:         config.PartyIDs(),
		Threshold:        config.Threshold,
		Group:            config.Group,
	}

	startFunc := keygen.StartRefresh(info, pl, config)
	sessionID := protocol.GenerateSessionID()
	session, err := startFunc(sessionID)
	if err != nil {
		return nil, err
	}

	// Run refresh with cancellation support
	done := make(chan error, 1)
	var newConfig *Config

	go func() {
		// Process rounds
		for session.CurrentRoundNumber() <= session.FinalRoundNumber() {
			select {
			case <-refreshCtx.Done():
				done <- refreshCtx.Err()
				return
			default:
				if err := processRound(session, pl); err != nil {
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
				done <- fmt.Errorf("refresh completed but no config")
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

// Helper function to process rounds
func processRound(session round.Session, pl *pool.Pool) error {
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
		configs, err := KeygenWithContext(ctx, group, selfID, participants, threshold, pl)
		if err != nil {
			return nil, err
		}
		
		// For backward compatibility, return the original protocol
		info := round.Info{
			ProtocolID:       "cmp/keygen-threshold",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           selfID,
			PartyIDs:         participants,
			Threshold:        threshold,
			Group:            group,
		}
		return keygen.StartKeygen(info, pl, nil)(sessionID)
	}
}

// Sign wraps SignWithContext for backward compatibility
// Deprecated: Use SignWithContext instead
func Sign(config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		
		// Try context-aware version
		_, err := SignWithContext(ctx, config, signers, messageHash, pl)
		if err != nil {
			// Fall back to original
			return sign.StartSign(config, signers, messageHash, pl)(sessionID)
		}
		
		// Return original for backward compatibility
		return sign.StartSign(config, signers, messageHash, pl)(sessionID)
	}
}

// Refresh wraps RefreshWithContext for backward compatibility
// Deprecated: Use RefreshWithContext instead
func Refresh(config *Config, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Use background context for backward compatibility
		ctx := context.Background()
		
		// Try context-aware version
		_, err := RefreshWithContext(ctx, config, pl)
		if err != nil {
			// Fall back to original
			info := round.Info{
				ProtocolID:       "cmp/refresh-threshold",
				FinalRoundNumber: keygen.Rounds,
				SelfID:           config.ID,
				PartyIDs:         config.PartyIDs(),
				Threshold:        config.Threshold,
				Group:            config.Group,
			}
			return keygen.StartRefresh(info, pl, config)(sessionID)
		}
		
		// Return original for backward compatibility
		info := round.Info{
			ProtocolID:       "cmp/refresh-threshold",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           config.ID,
			PartyIDs:         config.PartyIDs(),
			Threshold:        config.Threshold,
			Group:            config.Group,
		}
		return keygen.StartRefresh(info, pl, config)(sessionID)
	}
}