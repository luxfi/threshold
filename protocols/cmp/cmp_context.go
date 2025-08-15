// Package cmp implements context-aware CMP protocol operations
package cmp

import (
	"context"
	"fmt"
	"time"

	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/common"
	"golang.org/x/sync/errgroup"
)

// KeygenWithContext generates ECDSA keys with proper context handling
func KeygenWithContext(ctx context.Context, rt common.Runtime, cfg common.Config, deps common.Deps) ([]*Config, error) {
	// Validate inputs
	if err := common.ValidateRuntime(rt); err != nil {
		return nil, fmt.Errorf("invalid runtime: %w", err)
	}
	
	// Create timeout for keygen
	keygenCtx, cancel := context.WithTimeout(ctx, cfg.RoundTimeout*time.Duration(cfg.MaxRounds))
	defer cancel()
	
	// Initialize protocol handler
	handler, err := protocol.NewMultiHandler(newKeygen(rt, cfg, deps), nil)
	if err != nil {
		return nil, err
	}
	
	// Run protocol with context
	g, gCtx := errgroup.WithContext(keygenCtx)
	
	// Message processor
	g.Go(func() error {
		return processMessages(gCtx, handler, deps.Network)
	})
	
	// Round executor
	g.Go(func() error {
		return executeRounds(gCtx, handler, cfg)
	})
	
	// Wait for completion or cancellation
	if err := g.Wait(); err != nil {
		if err == context.DeadlineExceeded {
			return nil, fmt.Errorf("keygen timeout after %v", cfg.RoundTimeout*time.Duration(cfg.MaxRounds))
		}
		return nil, err
	}
	
	// Extract results
	return handler.Result().([]*Config), nil
}

// SignWithContext creates ECDSA signature with proper context handling
func SignWithContext(ctx context.Context, rt common.Runtime, config *Config, signers []party.ID, messageHash []byte, deps common.Deps) (*ecdsa.Signature, error) {
	// Create signing context with timeout
	signCtx, cancel := context.WithTimeout(ctx, rt.cfg.RoundTimeout*7) // 7 rounds for presigning
	defer cancel()
	
	// Initialize signing protocol
	handler, err := protocol.NewMultiHandler(newSign(rt, config, signers, messageHash, deps), nil)
	if err != nil {
		return nil, err
	}
	
	// Run signing protocol
	g, gCtx := errgroup.WithContext(signCtx)
	
	// Presigning phase
	g.Go(func() error {
		return runPresigning(gCtx, handler, deps)
	})
	
	// Online signing phase
	g.Go(func() error {
		select {
		case <-gCtx.Done():
			return gCtx.Err()
		case <-handler.PresigningComplete():
			return runOnlineSigning(gCtx, handler, messageHash, deps)
		}
	})
	
	// Wait for completion
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	
	return handler.Result().(*ecdsa.Signature), nil
}

// RefreshWithContext refreshes key shares with context support
func RefreshWithContext(ctx context.Context, rt common.Runtime, config *Config, deps common.Deps) (*Config, error) {
	// Create refresh context
	refreshCtx, cancel := context.WithTimeout(ctx, rt.cfg.RoundTimeout*4) // 4 rounds for refresh
	defer cancel()
	
	// Initialize refresh protocol
	handler, err := protocol.NewMultiHandler(newRefresh(rt, config, deps), nil)
	if err != nil {
		return nil, err
	}
	
	// Run refresh with cancellation support
	done := make(chan struct{})
	var refreshErr error
	
	go func() {
		defer close(done)
		refreshErr = runProtocol(refreshCtx, handler, deps)
	}()
	
	// Wait for completion or cancellation
	select {
	case <-refreshCtx.Done():
		return nil, fmt.Errorf("refresh timeout: %w", refreshCtx.Err())
	case <-done:
		if refreshErr != nil {
			return nil, refreshErr
		}
	}
	
	return handler.Result().(*Config), nil
}

// Helper functions

func processMessages(ctx context.Context, handler protocol.Handler, network protocol.Network) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-network.Receive():
			if err := handler.Accept(msg); err != nil {
				// Log error but continue processing
				continue
			}
		}
	}
}

func executeRounds(ctx context.Context, handler protocol.Handler, cfg common.Config) error {
	ticker := time.NewTicker(cfg.RoundTimeout)
	defer ticker.Stop()
	
	for round := 0; round < cfg.MaxRounds; round++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if handler.CanFinalize() {
				return handler.Finalize()
			}
			if err := handler.NextRound(); err != nil {
				return fmt.Errorf("round %d failed: %w", round, err)
			}
		}
	}
	
	return fmt.Errorf("protocol did not complete within %d rounds", cfg.MaxRounds)
}

func runProtocol(ctx context.Context, handler protocol.Handler, deps common.Deps) error {
	g, gCtx := errgroup.WithContext(ctx)
	
	// Message handler
	g.Go(func() error {
		return processMessages(gCtx, handler, deps.Network)
	})
	
	// Round executor
	g.Go(func() error {
		return executeRounds(gCtx, handler, deps.Config)
	})
	
	// Metrics collector
	if deps.Metrics != nil {
		g.Go(func() error {
			return collectMetrics(gCtx, handler, deps.Metrics)
		})
	}
	
	return g.Wait()
}

func collectMetrics(ctx context.Context, handler protocol.Handler, metrics common.MetricsCollector) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			stats := handler.Stats()
			metrics.RecordMessageCount("cmp", "total", stats.MessagesProcessed)
			metrics.RecordRoundLatency("cmp", stats.CurrentRound, stats.RoundDuration)
		}
	}
}

// Backward compatibility wrappers (to be deprecated)

// Keygen wraps KeygenWithContext for backward compatibility
// Deprecated: Use KeygenWithContext instead
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) ([]*Config, error) {
	ctx := context.Background()
	rt := common.Runtime{
		SessionID: protocol.GenerateSessionID(),
		SelfID:    selfID,
		PartyIDs:  participants,
		Threshold: threshold,
		Group:     group,
	}
	cfg := common.DefaultConfig()
	deps := common.Deps{
		Pool: pl,
	}
	return KeygenWithContext(ctx, rt, cfg, deps)
}

// Sign wraps SignWithContext for backward compatibility
// Deprecated: Use SignWithContext instead
func Sign(config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) (*ecdsa.Signature, error) {
	ctx := context.Background()
	rt := common.Runtime{
		SessionID: protocol.GenerateSessionID(),
		SelfID:    config.ID,
		PartyIDs:  config.PartyIDs(),
		Threshold: config.Threshold,
		Group:     config.Group,
	}
	cfg := common.DefaultConfig()
	deps := common.Deps{
		Pool: pl,
	}
	return SignWithContext(ctx, rt, config, signers, messageHash, deps)
}