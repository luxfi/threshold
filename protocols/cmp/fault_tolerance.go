package cmp

import (
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
)

// FaultTolerantCoordinator wraps signing operations with automatic failure detection
// and recovery through dynamic re-sharing
type FaultTolerantCoordinator struct {
	config          *Config
	pool           *pool.Pool
	
	// Failure tracking
	failureTracker  map[party.ID]*PartyHealth
	mu             sync.RWMutex
	
	// Recovery settings
	maxRetries      int
	failureThreshold int
	recoveryTimeout  time.Duration
	
	// State management
	generations     []*GenerationSnapshot
	currentGen      uint64
}

// PartyHealth tracks the reliability of a party
type PartyHealth struct {
	ID              party.ID
	FailureCount    int
	LastFailure     time.Time
	LastSuccess     time.Time
	ResponseTime    time.Duration
	IsResponsive    bool
}

// GenerationSnapshot stores a point-in-time configuration
type GenerationSnapshot struct {
	Generation   uint64
	Config       *Config
	PartyIDs     []party.ID
	Threshold    int
	Timestamp    time.Time
	HealthScores map[party.ID]float64
}

// NewFaultTolerantCoordinator creates a coordinator with automatic fault handling
func NewFaultTolerantCoordinator(config *Config, pl *pool.Pool) *FaultTolerantCoordinator {
	ftc := &FaultTolerantCoordinator{
		config:           config,
		pool:            pl,
		failureTracker:   make(map[party.ID]*PartyHealth),
		maxRetries:       3,
		failureThreshold: 2,
		recoveryTimeout:  30 * time.Second,
		generations:      make([]*GenerationSnapshot, 0),
		currentGen:       0,
	}
	
	// Initialize health tracking for all parties
	for _, id := range config.PartyIDs() {
		ftc.failureTracker[id] = &PartyHealth{
			ID:           id,
			IsResponsive: true,
		}
	}
	
	// Save initial generation
	ftc.saveGeneration()
	
	return ftc
}

// Sign attempts to generate a signature with automatic failure recovery
func (ftc *FaultTolerantCoordinator) Sign(messageHash []byte, requestedSigners []party.ID) (interface{}, error) {
	ftc.mu.RLock()
	currentConfig := ftc.config
	ftc.mu.RUnlock()
	
	// Filter to only healthy signers if not specified
	signers := ftc.selectHealthySigners(requestedSigners)
	
	// Attempt signing with retries
	for attempt := 0; attempt < ftc.maxRetries; attempt++ {
		result, failedParties, err := ftc.attemptSign(currentConfig, signers, messageHash)
		
		if err == nil {
			// Success - update health metrics
			ftc.updateHealthMetrics(signers, nil)
			return result, nil
		}
		
		// Track failures
		ftc.updateHealthMetrics(signers, failedParties)
		
		// Check if we need to trigger recovery
		if ftc.shouldTriggerRecovery(failedParties) {
			fmt.Printf("Triggering automatic recovery due to failures: %v\n", failedParties)
			
			newConfig, err := ftc.performRecovery(failedParties)
			if err != nil {
				return nil, fmt.Errorf("recovery failed: %w", err)
			}
			
			// Update config and retry with new configuration
			ftc.mu.Lock()
			ftc.config = newConfig
			currentConfig = newConfig
			ftc.mu.Unlock()
			
			// Select new signers from updated config
			signers = ftc.selectHealthySigners(nil)
		}
		
		// Wait before retry
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	
	return nil, fmt.Errorf("signing failed after %d attempts", ftc.maxRetries)
}

// attemptSign tries to generate a signature with the given configuration
func (ftc *FaultTolerantCoordinator) attemptSign(config *Config, signers []party.ID, messageHash []byte) (interface{}, []party.ID, error) {
	// Create signing session
	handler := protocol.NewMultiHandler(Sign(config, signers, messageHash, ftc.pool), nil)
	
	// Track which parties respond
	respondingParties := make(map[party.ID]bool)
	failedParties := make([]party.ID, 0)
	
	// Simulate protocol execution with timeout
	timeout := time.After(ftc.recoveryTimeout)
	done := make(chan bool)
	var result interface{}
	var err error
	
	go func() {
		// In real implementation, this would handle actual protocol rounds
		result, err = handler.Result()
		done <- true
	}()
	
	select {
	case <-done:
		if err != nil {
			// Determine which parties failed
			for _, signer := range signers {
				if !respondingParties[signer] {
					failedParties = append(failedParties, signer)
				}
			}
		}
		return result, failedParties, err
		
	case <-timeout:
		// Timeout - all non-responding parties are considered failed
		for _, signer := range signers {
			if !respondingParties[signer] {
				failedParties = append(failedParties, signer)
			}
		}
		return nil, failedParties, fmt.Errorf("signing timeout")
	}
}

// selectHealthySigners chooses responsive parties for signing
func (ftc *FaultTolerantCoordinator) selectHealthySigners(requested []party.ID) []party.ID {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()
	
	// If specific signers requested, filter for health
	if len(requested) > 0 {
		healthy := make([]party.ID, 0)
		for _, id := range requested {
			if health, ok := ftc.failureTracker[id]; ok && health.IsResponsive {
				healthy = append(healthy, id)
			}
		}
		return healthy
	}
	
	// Otherwise, select threshold+1 healthiest parties
	allParties := ftc.config.PartyIDs()
	healthyParties := make([]party.ID, 0)
	
	for _, id := range allParties {
		if health, ok := ftc.failureTracker[id]; ok && health.IsResponsive {
			healthyParties = append(healthyParties, id)
		}
	}
	
	// Need at least threshold parties
	if len(healthyParties) < ftc.config.Threshold {
		// Include some less healthy parties
		for _, id := range allParties {
			if len(healthyParties) >= ftc.config.Threshold+1 {
				break
			}
			
			alreadyIncluded := false
			for _, hid := range healthyParties {
				if hid == id {
					alreadyIncluded = true
					break
				}
			}
			
			if !alreadyIncluded {
				healthyParties = append(healthyParties, id)
			}
		}
	}
	
	// Return threshold+1 parties
	if len(healthyParties) > ftc.config.Threshold+1 {
		return healthyParties[:ftc.config.Threshold+1]
	}
	
	return healthyParties
}

// updateHealthMetrics updates party health based on signing results
func (ftc *FaultTolerantCoordinator) updateHealthMetrics(attempted []party.ID, failed []party.ID) {
	ftc.mu.Lock()
	defer ftc.mu.Unlock()
	
	now := time.Now()
	
	// Mark failures
	for _, id := range failed {
		if health, ok := ftc.failureTracker[id]; ok {
			health.FailureCount++
			health.LastFailure = now
			
			// Mark unresponsive after threshold failures
			if health.FailureCount >= ftc.failureThreshold {
				health.IsResponsive = false
			}
		}
	}
	
	// Mark successes
	for _, id := range attempted {
		isFailed := false
		for _, fid := range failed {
			if id == fid {
				isFailed = true
				break
			}
		}
		
		if !isFailed {
			if health, ok := ftc.failureTracker[id]; ok {
				health.LastSuccess = now
				health.FailureCount = 0 // Reset on success
				health.IsResponsive = true
			}
		}
	}
}

// shouldTriggerRecovery determines if automatic recovery is needed
func (ftc *FaultTolerantCoordinator) shouldTriggerRecovery(failedParties []party.ID) bool {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()
	
	// Count total unresponsive parties
	unresponsiveCount := 0
	for _, health := range ftc.failureTracker {
		if !health.IsResponsive {
			unresponsiveCount++
		}
	}
	
	totalParties := len(ftc.config.PartyIDs())
	healthyParties := totalParties - unresponsiveCount
	
	// Trigger if we don't have enough healthy parties for threshold
	return healthyParties < ftc.config.Threshold+1
}

// performRecovery executes automatic recovery by removing failed parties
func (ftc *FaultTolerantCoordinator) performRecovery(failedParties []party.ID) (*Config, error) {
	ftc.mu.Lock()
	defer ftc.mu.Unlock()
	
	// Identify parties to remove (consistently failing ones)
	partiesToRemove := make([]party.ID, 0)
	for id, health := range ftc.failureTracker {
		if !health.IsResponsive && health.FailureCount >= ftc.failureThreshold {
			partiesToRemove = append(partiesToRemove, id)
		}
	}
	
	if len(partiesToRemove) == 0 {
		return ftc.config, nil
	}
	
	fmt.Printf("Removing unresponsive parties: %v\n", partiesToRemove)
	
	// Calculate new threshold if needed
	remainingParties := len(ftc.config.PartyIDs()) - len(partiesToRemove)
	newThreshold := ftc.config.Threshold
	
	// Adjust threshold if necessary
	if newThreshold > remainingParties-1 {
		newThreshold = remainingParties/2 + 1
		if newThreshold < 1 {
			newThreshold = 1
		}
	}
	
	// Execute dynamic reshare to remove failed parties
	handler := protocol.NewMultiHandler(
		RemoveParties(ftc.config, partiesToRemove, newThreshold, ftc.pool),
		nil,
	)
	
	// Run the resharing protocol
	result, err := handler.Result()
	if err != nil {
		// If resharing fails, try rolling back to previous generation
		return ftc.rollbackToPreviousGeneration()
	}
	
	newConfig := result.(*Config)
	
	// Save new generation
	ftc.currentGen++
	ftc.saveGenerationWithConfig(newConfig)
	
	// Reset health tracking for remaining parties
	for _, id := range partiesToRemove {
		delete(ftc.failureTracker, id)
	}
	
	return newConfig, nil
}

// rollbackToPreviousGeneration reverts to a previous known-good state
func (ftc *FaultTolerantCoordinator) rollbackToPreviousGeneration() (*Config, error) {
	if len(ftc.generations) < 2 {
		return nil, fmt.Errorf("no previous generation to rollback to")
	}
	
	// Get previous generation
	prevGen := ftc.generations[len(ftc.generations)-2]
	
	fmt.Printf("Rolling back to generation %d\n", prevGen.Generation)
	
	// Restore health metrics from that generation
	for id, score := range prevGen.HealthScores {
		if health, ok := ftc.failureTracker[id]; ok {
			health.IsResponsive = score > 0.5
			health.FailureCount = 0
		}
	}
	
	return prevGen.Config, nil
}

// saveGeneration creates a snapshot of current state
func (ftc *FaultTolerantCoordinator) saveGeneration() {
	ftc.saveGenerationWithConfig(ftc.config)
}

// saveGenerationWithConfig creates a snapshot with specific config
func (ftc *FaultTolerantCoordinator) saveGenerationWithConfig(config *Config) {
	healthScores := make(map[party.ID]float64)
	
	for id, health := range ftc.failureTracker {
		score := 1.0
		if health.FailureCount > 0 {
			score = 1.0 / float64(1+health.FailureCount)
		}
		if !health.IsResponsive {
			score = 0.0
		}
		healthScores[id] = score
	}
	
	snapshot := &GenerationSnapshot{
		Generation:   ftc.currentGen,
		Config:       config,
		PartyIDs:     config.PartyIDs(),
		Threshold:    config.Threshold,
		Timestamp:    time.Now(),
		HealthScores: healthScores,
	}
	
	ftc.generations = append(ftc.generations, snapshot)
	
	// Keep only last 10 generations
	if len(ftc.generations) > 10 {
		ftc.generations = ftc.generations[1:]
	}
}

// GetHealthReport returns current health status of all parties
func (ftc *FaultTolerantCoordinator) GetHealthReport() map[party.ID]*PartyHealth {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()
	
	report := make(map[party.ID]*PartyHealth)
	for id, health := range ftc.failureTracker {
		// Create a copy
		report[id] = &PartyHealth{
			ID:           health.ID,
			FailureCount: health.FailureCount,
			LastFailure:  health.LastFailure,
			LastSuccess:  health.LastSuccess,
			ResponseTime: health.ResponseTime,
			IsResponsive: health.IsResponsive,
		}
	}
	
	return report
}

// ManualRecovery allows triggering recovery for specific parties
func (ftc *FaultTolerantCoordinator) ManualRecovery(partiesToEvict []party.ID) error {
	newConfig, err := ftc.performRecovery(partiesToEvict)
	if err != nil {
		return err
	}
	
	ftc.mu.Lock()
	ftc.config = newConfig
	ftc.mu.Unlock()
	
	return nil
}