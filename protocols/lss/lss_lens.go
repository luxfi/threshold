// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lss — Lens adapter.
//
// This file is the LSS-Lens adapter: it wires the LSS dynamic-resharing
// lifecycle (Generation tracking, snapshot history, rollback) into the
// Lens curve threshold kernel (curve scalar share representation,
// Pedersen commitments over G/H, FROST-compatible signing material).
//
// Architectural contract:
//
//   LSS owns:
//     - Generation numbers and version monotonicity
//     - GenerationSnapshot history and Rollback semantics
//     - Bootstrap Dealer / Signature Coordinator role separation
//     - Live resharing orchestration shape
//
//   Lens (kernel) owns:
//     - Curve scalar share representation and Shamir over the scalar field
//     - Pedersen commits (s·G + r·H) over the curve
//     - FROST 2-round Sign / Aggregate (RFC 9591)
//     - Lambda + pairwise material regeneration
//     - Activation cert message bytes (curve Schnorr signature)
//
//   This adapter (lss_lens.go) does:
//     1. Validate the LSS lifecycle constraints (consistent KeyEraID
//        across old configs, threshold sanity, qualified-old-set size).
//     2. Call into lens/keyera + lens/reshare for the curve math.
//     3. Bump Generation; wire RollbackFrom on rollback paths.
//     4. Persist snapshots through the LSS-style snapshot store.
//
// What this adapter must NOT do:
//
//   - Reimplement Lens VSR math (commits, complaints, transcript). That
//     lives in github.com/luxfi/lens/reshare and is called via
//     lens.KeyEra.Reshare.
//   - Inherit ECDSA-specific assumptions from LSS-CMP / LSS-FROST stub
//     (auxiliary secrets w, q; multiplicative nonce blinding). FROST's
//     signing protocol has additive nonce (d_i, e_i) blinding built into
//     Round 1; no w, q needed.
//   - Invent its own rollback semantics. Use the snapshot store; on
//     activation failure, return an error and let the caller decide.

package lss

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"

	"github.com/luxfi/lens/hash"
	"github.com/luxfi/lens/keyera"
	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/reshare"
	lensThreshold "github.com/luxfi/lens/threshold"
)

// LensConfig is the LSS-Lens adapter's per-party configuration.
// Wraps a lens.EpochShareState so the adapter can apply LSS lifecycle
// semantics uniformly. Generation and RollbackFrom on the embedded
// EpochShareState are the source of truth — the wrapper exists to
// match the FROST/CMP/Pulsar adapter shape.
//
// NebulaRoot, HashSuiteID, and ImplementationVersion are optional
// transcript-binding fields that flow through to the activation
// message. They MAY be left zero / empty at the adapter call site;
// BuildLensActivationTranscript supplies sensible defaults
// ("Lens-SHA3", "lss-lens-test-1.0", zero NebulaRoot) when fields
// are unset.
type LensConfig struct {
	// State is the underlying Lens share state. Generation and
	// RollbackFrom live inside State (not duplicated on the wrapper).
	State *keyera.EpochShareState

	// PartyID is the wire-identity of this party.
	PartyID party.ID

	// NebulaRoot binds the share state to a specific Quasar Nebula
	// frontier or epoch root anchor. Zero by default; set when the
	// caller wants the activation cert to commit to a specific chain
	// state moment.
	NebulaRoot [32]byte

	// HashSuiteID pins the hash profile this config was produced
	// under. Empty defaults to "Lens-SHA3" inside
	// BuildLensActivationTranscript.
	HashSuiteID string

	// ImplementationVersion pins the software-port identity. Empty
	// defaults to "lss-lens-test-1.0".
	ImplementationVersion string
}

// Generation returns the LSS resharing generation. Pass-through to
// the underlying Lens state; aligns with the lifecycle field LSS reads.
func (lc *LensConfig) Generation() uint64 {
	if lc == nil || lc.State == nil {
		return 0
	}
	return lc.State.Generation
}

// RollbackFrom returns the previous generation when this state
// descends from a Rollback; zero on ordinary forward transitions.
func (lc *LensConfig) RollbackFrom() uint64 {
	if lc == nil || lc.State == nil {
		return 0
	}
	return lc.State.RollbackFrom
}

// KeyEraID returns the Lens group-key lineage ID. Stable across every
// Reshare within a key era; bumps only at Reanchor.
func (lc *LensConfig) KeyEraID() uint64 {
	if lc == nil || lc.State == nil {
		return 0
	}
	return lc.State.KeyEraID
}

// Default values used by BuildLensActivationTranscript when a config
// does not set HashSuiteID / ImplementationVersion explicitly.
const (
	defaultLensHashSuiteID           = hash.DefaultID // "Lens-SHA3"
	defaultLensImplementationVersion = "lss-lens-test-1.0"
)

// BuildLensActivationTranscript returns a fully-populated
// reshare.TranscriptInputs binding (chain_id, network_id, group_id,
// key_era_id, generations, epochs, sets, thresholds, group_pk_hash,
// nebula_root, hash_suite_id, implementation_version, variant, curve)
// for the activation cert the new committee will threshold-sign under
// the unchanged GroupKey.
//
// Inputs:
//
//   - oldCfgs    — the configs that fed DynamicReshareLens.
//   - newCfgs    — the configs returned by DynamicReshareLens.
//   - chainID, networkID, groupID — wire-level identifiers.
//   - groupPubKeyHash — 32-byte digest over the canonical GroupKey
//     bytes. Caller computes once at era bootstrap and reuses across
//     every reshare in the era.
//   - nebulaRoot — Quasar frontier anchor; zero acceptable.
//   - hashSuiteID, implVersion — pinned profile and port identifiers;
//     empty values resolve to the package defaults.
//   - variant — "refresh" or "reshare".
//   - suite — HashSuite for the validator-set hashes; nil = default.
func BuildLensActivationTranscript(
	oldCfgs map[party.ID]*LensConfig,
	newCfgs map[party.ID]*LensConfig,
	chainID, networkID, groupID []byte,
	groupPubKeyHash [32]byte,
	nebulaRoot [32]byte,
	hashSuiteID, implVersion, variant string,
	suite hash.HashSuite,
) reshare.TranscriptInputs {
	if hashSuiteID == "" {
		hashSuiteID = defaultLensHashSuiteID
	}
	if implVersion == "" {
		implVersion = defaultLensImplementationVersion
	}

	var (
		eraID              uint64
		oldGen, newGen     uint64
		oldT, newT         int
		oldEpoch, newEpoch uint64
		oldKeys, newKeys   [][]byte
		curveName          string
	)
	for _, c := range oldCfgs {
		if c == nil || c.State == nil {
			continue
		}
		eraID = c.State.KeyEraID
		oldGen = c.State.Generation
		oldT = c.State.Threshold
		oldEpoch = c.State.Epoch
		oldKeys = make([][]byte, len(c.State.Validators))
		for i, v := range c.State.Validators {
			oldKeys[i] = []byte(v)
		}
		// Derive curve name from the first share we find.
		for _, ks := range c.State.Shares {
			if ks.GroupKey != nil {
				curveName = ks.GroupKey.Curve.Name()
			}
			break
		}
		break
	}
	for _, c := range newCfgs {
		if c == nil || c.State == nil {
			continue
		}
		newGen = c.State.Generation
		newT = c.State.Threshold
		newEpoch = c.State.Epoch
		newKeys = make([][]byte, len(c.State.Validators))
		for i, v := range c.State.Validators {
			newKeys[i] = []byte(v)
		}
		break
	}

	return reshare.TranscriptInputs{
		ChainID:               chainID,
		NetworkID:             networkID,
		GroupID:               groupID,
		KeyEraID:              eraID,
		OldGeneration:         oldGen,
		NewGeneration:         newGen,
		OldEpochID:            oldEpoch,
		NewEpochID:            newEpoch,
		OldSetHash:            reshare.ValidatorSetHash(oldKeys, suite),
		NewSetHash:            reshare.ValidatorSetHash(newKeys, suite),
		ThresholdOld:          uint32(oldT),
		ThresholdNew:          uint32(newT),
		GroupPublicKeyHash:    groupPubKeyHash,
		NebulaRoot:            nebulaRoot,
		HashSuiteID:           hashSuiteID,
		ImplementationVersion: implVersion,
		Variant:               variant,
		CurveName:             curveName,
	}
}

// Errors returned by the LSS-Lens adapter.
var (
	ErrLensNoOldConfigs        = errors.New("lss-lens: no old configurations provided")
	ErrLensInvalidThreshold    = errors.New("lss-lens: invalid new threshold")
	ErrLensKeyEraMismatch      = errors.New("lss-lens: old configs span multiple key eras")
	ErrLensGenerationMismatch  = errors.New("lss-lens: old configs span multiple generations")
	ErrLensGroupKeyMismatch    = errors.New("lss-lens: old configs disagree on GroupKey pointer")
	ErrLensInsufficientOldSet  = errors.New("lss-lens: insufficient old configs to form qualified set")
	ErrLensMissingShare        = errors.New("lss-lens: old config missing share")
	ErrLensKernelReshareFailed = errors.New("lss-lens: lens kernel reshare failed")
)

// DynamicReshareLens performs LSS dynamic resharing on Lens
// configurations. Implements the LSS Section 4 lifecycle adapted for
// the Lens curve setting:
//
//  1. Validate that all old configs agree on KeyEraID, Generation,
//     and GroupKey (they should — they came from the same era at the
//     same generation).
//  2. Reconstruct the in-process lens.KeyEra from the agreed-on
//     GroupKey + the union of old shares.
//  3. Call lens.KeyEra.Reshare with the new participant set + new
//     threshold. The kernel handles all curve math: Reshare polynomial
//     sampling, Lagrange interpolation over the old qualified set,
//     Pedersen commits over the curve, Lambda recomputation, Seeds +
//     MACKeys regeneration.
//  4. Wrap the resulting EpochShareState into LensConfigs, one per
//     new party. Generation is bumped by the kernel; KeyEraID is
//     preserved; RollbackFrom is zero (forward transition).
//
// Adapter contract guarantees:
//
//	Preserved across the call: KeyEraID, GroupKey pointer, master
//	  secret s (held only as shares; never reconstructed in this
//	  process), and the persistent group public key X = s·G.
//
//	Changed across the call: Generation (incremented by 1),
//	  participant set, threshold, share values, Lambdas, pairwise PRF
//	  Seeds, MAC keys, transcript hash.
//
// Failure behavior: returns an error. The caller (LSS RollbackManager
// or Quasar consensus) decides whether to retry, rollback, or
// reanchor. The adapter does not silently fall back.
//
// rand defaults to crypto/rand.Reader. Tests pass a deterministic
// source for KAT replay.
func DynamicReshareLens(
	oldConfigs map[party.ID]*LensConfig,
	newPartyIDs []party.ID,
	newThreshold int,
	_ *pool.Pool,
	rand io.Reader,
) (map[party.ID]*LensConfig, error) {
	if len(oldConfigs) == 0 {
		return nil, ErrLensNoOldConfigs
	}
	if newThreshold < 1 || newThreshold > len(newPartyIDs) {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrLensInvalidThreshold, newThreshold, len(newPartyIDs))
	}

	// 1. Validate consistency.
	var (
		refKeyEraID   uint64
		refGen        uint64
		refGroupKey   *lensThreshold.GroupKey
		refValidators []string
		refThreshold  int
		first         = true
	)
	for _, cfg := range oldConfigs {
		if cfg == nil || cfg.State == nil {
			return nil, ErrLensMissingShare
		}
		if first {
			refKeyEraID = cfg.State.KeyEraID
			refGen = cfg.State.Generation
			refValidators = cfg.State.Validators
			refThreshold = cfg.State.Threshold
			first = false
			for _, ks := range cfg.State.Shares {
				refGroupKey = ks.GroupKey
				break
			}
			continue
		}
		if cfg.State.KeyEraID != refKeyEraID {
			return nil, fmt.Errorf("%w: era %d != %d",
				ErrLensKeyEraMismatch, cfg.State.KeyEraID, refKeyEraID)
		}
		if cfg.State.Generation != refGen {
			return nil, fmt.Errorf("%w: gen %d != %d",
				ErrLensGenerationMismatch, cfg.State.Generation, refGen)
		}
		for _, ks := range cfg.State.Shares {
			if ks.GroupKey != refGroupKey {
				return nil, ErrLensGroupKeyMismatch
			}
			break
		}
	}
	if refGroupKey == nil {
		return nil, ErrLensMissingShare
	}

	if refThreshold > len(oldConfigs) {
		return nil, fmt.Errorf("%w: have %d configs, need %d",
			ErrLensInsufficientOldSet, len(oldConfigs), refThreshold)
	}

	// 3. Reconstruct the lens.KeyEra from the union of old shares.
	era := &keyera.KeyEra{
		EraID:        keyera.LensKeyEraID(refKeyEraID),
		GroupKey:     refGroupKey,
		GenesisEpoch: 0,
		State: &keyera.EpochShareState{
			KeyEraID:   refKeyEraID,
			Generation: refGen,
			Epoch:      0,
			Validators: refValidators,
			Threshold:  refThreshold,
			Shares:     make(map[string]*lensThreshold.KeyShare, len(oldConfigs)),
		},
	}
	for _, cfg := range oldConfigs {
		for v, ks := range cfg.State.Shares {
			era.State.Shares[v] = ks
		}
	}

	// 4. Call into the Lens kernel for all curve math.
	newValidators := make([]string, len(newPartyIDs))
	for i, id := range newPartyIDs {
		newValidators[i] = string(id)
	}
	nextState, err := era.Reshare(newValidators, newThreshold, rand)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLensKernelReshareFailed, err)
	}

	// 5. Wrap each new share into a LensConfig, one per new party.
	out := make(map[party.ID]*LensConfig, len(newPartyIDs))
	for _, id := range newPartyIDs {
		v := string(id)
		share, ok := nextState.Shares[v]
		if !ok {
			return nil, fmt.Errorf("lss-lens: kernel did not return share for %s", v)
		}
		perPartyState := &keyera.EpochShareState{
			KeyEraID:     nextState.KeyEraID,
			Generation:   nextState.Generation,
			RollbackFrom: 0,
			Epoch:        nextState.Epoch,
			Validators:   nextState.Validators,
			Threshold:    nextState.Threshold,
			Shares:       map[string]*lensThreshold.KeyShare{v: share},
		}
		out[id] = &LensConfig{
			State:   perPartyState,
			PartyID: id,
		}
	}
	return out, nil
}

// LensSnapshotManager is a per-Lens-era snapshot store. Mirrors the
// shape of LSS's RollbackManager but typed to LensConfig.
type LensSnapshotManager struct {
	mu             sync.RWMutex
	history        []*LensSnapshot
	maxGenerations int
	currentGen     uint64
}

// LensSnapshot is a point-in-time snapshot of a Lens key era's share
// state, suitable for rollback.
type LensSnapshot struct {
	KeyEraID   uint64
	Generation uint64
	State      *keyera.EpochShareState
	PartyIDs   []party.ID
	Threshold  int
}

// NewLensSnapshotManager creates a snapshot store keeping at most
// maxGenerations entries. Default 10 if maxGenerations < 1.
func NewLensSnapshotManager(maxGenerations int) *LensSnapshotManager {
	if maxGenerations < 1 {
		maxGenerations = 10
	}
	return &LensSnapshotManager{
		history:        make([]*LensSnapshot, 0, maxGenerations),
		maxGenerations: maxGenerations,
	}
}

// SaveSnapshot persists a per-generation snapshot. Should be called
// by the Signature Coordinator after a successful Reshare/Refresh
// activates.
func (lsm *LensSnapshotManager) SaveSnapshot(state *keyera.EpochShareState, partyIDs []party.ID) error {
	if state == nil {
		return errors.New("lss-lens: cannot save nil state")
	}
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	snap := &LensSnapshot{
		KeyEraID:   state.KeyEraID,
		Generation: state.Generation,
		State:      state,
		PartyIDs:   append([]party.ID(nil), partyIDs...),
		Threshold:  state.Threshold,
	}
	lsm.history = append(lsm.history, snap)
	if state.Generation > lsm.currentGen {
		lsm.currentGen = state.Generation
	}
	if len(lsm.history) > lsm.maxGenerations {
		lsm.history = lsm.history[len(lsm.history)-lsm.maxGenerations:]
	}
	return nil
}

// Rollback restores the share state at a target generation. Marks the
// restored state with RollbackFrom = currentGen and Generation =
// currentGen + 1.
func (lsm *LensSnapshotManager) Rollback(targetGeneration uint64) (*keyera.EpochShareState, error) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	if targetGeneration >= lsm.currentGen {
		return nil, fmt.Errorf("lss-lens: cannot rollback to future generation %d (current: %d)",
			targetGeneration, lsm.currentGen)
	}
	var target *LensSnapshot
	for i := len(lsm.history) - 1; i >= 0; i-- {
		if lsm.history[i].Generation == targetGeneration {
			target = lsm.history[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("lss-lens: generation %d not in history", targetGeneration)
	}

	restored := *target.State
	restored.Generation = lsm.currentGen + 1
	restored.RollbackFrom = lsm.currentGen
	lsm.currentGen = restored.Generation
	return &restored, nil
}

// CurrentGeneration returns the most recently saved generation.
func (lsm *LensSnapshotManager) CurrentGeneration() uint64 {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()
	return lsm.currentGen
}

// HistorySize returns the number of snapshots currently retained.
func (lsm *LensSnapshotManager) HistorySize() int {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()
	return len(lsm.history)
}

// CurveForLens is a small helper exposing the default curve to test
// callers — keeps the test file from importing primitives directly.
func CurveForLens() primitives.Curve {
	return primitives.NewEd25519()
}
