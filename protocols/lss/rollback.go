package lss

import (
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// RollbackManager manages configuration history and rollback operations
type RollbackManager struct {
	mu              sync.RWMutex
	history         []*GenerationSnapshot
	maxGenerations  int
	currentGen      uint64
}

// GenerationSnapshot represents a point-in-time configuration state
type GenerationSnapshot struct {
	Generation   uint64
	Config       *config.Config
	PartyIDs     []party.ID
	Threshold    int
	Timestamp    int64
	FailureCount int
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(maxGenerations int) *RollbackManager {
	if maxGenerations < 1 {
		maxGenerations = 10 // Default to keeping 10 generations
	}
	return &RollbackManager{
		history:        make([]*GenerationSnapshot, 0, maxGenerations),
		maxGenerations: maxGenerations,
	}
}

// SaveSnapshot saves a configuration snapshot for potential rollback
func (rm *RollbackManager) SaveSnapshot(cfg *config.Config) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if cfg == nil {
		return errors.New("cannot save nil configuration")
	}

	snapshot := &GenerationSnapshot{
		Generation: cfg.Generation,
		Config:     cfg.Copy(), // Deep copy to preserve state
		PartyIDs:   cfg.PartyIDs(),
		Threshold:  cfg.Threshold,
		Timestamp:  timeNow(),
	}

	rm.history = append(rm.history, snapshot)
	rm.currentGen = cfg.Generation

	// Trim history if it exceeds max generations
	if len(rm.history) > rm.maxGenerations {
		rm.history = rm.history[len(rm.history)-rm.maxGenerations:]
	}

	return nil
}

// Rollback reverts to a previous generation
func (rm *RollbackManager) Rollback(targetGeneration uint64) (*config.Config, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if targetGeneration >= rm.currentGen {
		return nil, fmt.Errorf("cannot rollback to future generation %d (current: %d)", 
			targetGeneration, rm.currentGen)
	}

	// Find the target snapshot
	var targetSnapshot *GenerationSnapshot
	for i := len(rm.history) - 1; i >= 0; i-- {
		if rm.history[i].Generation == targetGeneration {
			targetSnapshot = rm.history[i]
			break
		}
	}

	if targetSnapshot == nil {
		return nil, fmt.Errorf("generation %d not found in history", targetGeneration)
	}

	// Create a new config from the snapshot
	restoredConfig := targetSnapshot.Config.Copy()
	
	// Mark this as a rollback by incrementing the generation
	// This ensures we can track that a rollback occurred
	restoredConfig.Generation = rm.currentGen + 1
	restoredConfig.RollbackFrom = rm.currentGen

	// Update current generation
	rm.currentGen = restoredConfig.Generation

	return restoredConfig, nil
}

// RollbackOnFailure automatically rolls back if failure count exceeds threshold
func (rm *RollbackManager) RollbackOnFailure(failureThreshold int) (*config.Config, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.history) < 2 {
		return nil, errors.New("insufficient history for rollback")
	}

	currentSnapshot := rm.history[len(rm.history)-1]
	currentSnapshot.FailureCount++

	if currentSnapshot.FailureCount >= failureThreshold {
		// Roll back to previous generation
		previousSnapshot := rm.history[len(rm.history)-2]
		
		restoredConfig := previousSnapshot.Config.Copy()
		restoredConfig.Generation = rm.currentGen + 1
		restoredConfig.RollbackFrom = rm.currentGen
		
		// Reset failure count after rollback
		previousSnapshot.FailureCount = 0
		
		rm.currentGen = restoredConfig.Generation
		return restoredConfig, nil
	}

	return nil, fmt.Errorf("failure count %d below threshold %d", 
		currentSnapshot.FailureCount, failureThreshold)
}

// GetHistory returns the configuration history
func (rm *RollbackManager) GetHistory() []*GenerationSnapshot {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	history := make([]*GenerationSnapshot, len(rm.history))
	copy(history, rm.history)
	return history
}

// ClearHistory removes all stored snapshots
func (rm *RollbackManager) ClearHistory() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.history = rm.history[:0]
}

// EvictParties removes specified parties from the current configuration
func (rm *RollbackManager) EvictParties(cfg *config.Config, evictedParties []party.ID) (*config.Config, error) {
	if cfg == nil {
		return nil, errors.New("configuration is nil")
	}

	// Create a set of evicted parties for efficient lookup
	evicted := make(map[party.ID]bool)
	for _, p := range evictedParties {
		evicted[p] = true
	}

	// Build new party list excluding evicted parties
	newParties := make([]party.ID, 0)
	for _, p := range cfg.PartyIDs() {
		if !evicted[p] {
			newParties = append(newParties, p)
		}
	}

	// Ensure we still have enough parties for the threshold
	if len(newParties) < cfg.Threshold {
		return nil, fmt.Errorf("eviction would leave %d parties, below threshold %d", 
			len(newParties), cfg.Threshold)
	}

	// Create new configuration without evicted parties
	// This would trigger a resharing protocol in practice
	newConfig := cfg.Copy()
	newConfig.Generation++
	
	// Update public keys map to remove evicted parties
	for p := range evicted {
		delete(newConfig.Public, p)
	}

	return newConfig, nil
}

// timeNow returns current Unix timestamp (mockable for testing)
var timeNow = func() int64 {
	return timeNowUnix()
}

func timeNowUnix() int64 {
	return int64(0) // Simplified for now, would use time.Now().Unix() in production
}

// Global rollback manager instance
var defaultRollbackManager = NewRollbackManager(10)

// Rollback performs a rollback to a previous generation
func Rollback(cfg *config.Config, targetGeneration uint64) (*config.Config, error) {
	// Save current state if not already saved
	if err := defaultRollbackManager.SaveSnapshot(cfg); err != nil {
		return nil, fmt.Errorf("failed to save current state: %w", err)
	}
	
	return defaultRollbackManager.Rollback(targetGeneration)
}

// RollbackOnFailure triggers automatic rollback after repeated failures
func RollbackOnFailure(cfg *config.Config, failureThreshold int) (*config.Config, error) {
	if err := defaultRollbackManager.SaveSnapshot(cfg); err != nil {
		return nil, fmt.Errorf("failed to save current state: %w", err)
	}
	
	return defaultRollbackManager.RollbackOnFailure(failureThreshold)
}

// EvictAndRollback evicts problematic parties and rolls back if needed
func EvictAndRollback(cfg *config.Config, evictedParties []party.ID) (*config.Config, error) {
	// First try to evict parties
	newConfig, err := defaultRollbackManager.EvictParties(cfg, evictedParties)
	if err != nil {
		// If eviction fails, rollback to previous generation
		return defaultRollbackManager.Rollback(cfg.Generation - 1)
	}
	
	// Save the new configuration
	if err := defaultRollbackManager.SaveSnapshot(newConfig); err != nil {
		return nil, fmt.Errorf("failed to save eviction state: %w", err)
	}
	
	return newConfig, nil
}