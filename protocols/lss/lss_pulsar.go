// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lss — Pulsar adapter.
//
// This file is the LSS-Pulsar adapter: it wires LSS dynamic-resharing
// lifecycle (Generation tracking, snapshot history, rollback) into
// Pulsar's lattice threshold kernel (R_q share representation,
// Pedersen commitments, Corona-compatible signing material).
//
// Architectural contract (per pulsar/DESIGN.md):
//
//   LSS owns:
//     - Generation numbers and version monotonicity
//     - GenerationSnapshot history and Rollback semantics
//     - Bootstrap Dealer / Signature Coordinator role separation
//     - Live resharing orchestration shape
//
//   Pulsar (kernel) owns:
//     - R_q share representation and Shamir over R_q
//     - Pedersen commits (A·NTT(s) + B·NTT(r)) over R_q
//     - Corona Sign1/Sign2/Combine
//     - Lambda + PRF Seeds + MACKeys regeneration
//     - Activation cert message bytes (lattice signature)
//
//   This adapter (lss_pulsar.go) does:
//     1. Validate the LSS lifecycle constraints (consistent KeyEraID
//        across old configs, threshold sanity, qualified-old-set size).
//     2. Call into pulsar/keyera + pulsar/reshare for the lattice math.
//     3. Bump Generation; wire RollbackFrom on rollback paths.
//     4. Persist snapshots through the LSS-style snapshot store.
//
// What this adapter must NOT do:
//
//   - Reimplement Pulsar VSR math (commits, complaints, transcript).
//     That lives in github.com/luxfi/corona/reshare and is called via
//     pulsar.KeyEra.Reshare.
//   - Inherit ECDSA-specific assumptions from LSS-CMP / LSS-FROST
//     (auxiliary secrets w, q; curve.Point commits; nonce blinding).
//     Pulsar/Corona's signing protocol has Gaussian blinding built
//     into Sign1/Sign2; no w, q needed.
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

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/keyera"
	"github.com/luxfi/corona/reshare"
	pulsarThreshold "github.com/luxfi/corona/threshold"
)

// PulsarConfig is the LSS-Pulsar adapter's per-party configuration.
// Wraps a pulsar.EpochShareState so the adapter can apply LSS lifecycle
// semantics uniformly. Generation and RollbackFrom on the embedded
// EpochShareState are the source of truth — the wrapper exists to
// match the FROST/CMP adapter shape.
//
// NebulaRoot, HashSuiteID, and ImplementationVersion are optional
// transcript-binding fields that flow through to the activation
// message. They MAY be left zero / empty at the adapter call site;
// BuildActivationTranscript supplies sensible defaults
// ("Pulsar-SHA3", "lss-pulsar-test-1.0", zero-NebulaRoot) when fields
// are unset.
type PulsarConfig struct {
	// State is the underlying Pulsar share state. Generation and
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
	// under. Empty defaults to "Pulsar-SHA3" inside
	// BuildActivationTranscript.
	HashSuiteID string

	// ImplementationVersion pins the software-port identity. Empty
	// defaults to "lss-pulsar-test-1.0".
	ImplementationVersion string
}

// Generation returns the LSS resharing generation. Pass-through to the
// underlying Pulsar state; aligns with the lifecycle field LSS reads.
func (pc *PulsarConfig) Generation() uint64 {
	if pc == nil || pc.State == nil {
		return 0
	}
	return pc.State.Generation
}

// RollbackFrom returns the previous generation when this state
// descends from a Rollback; zero on ordinary forward transitions.
func (pc *PulsarConfig) RollbackFrom() uint64 {
	if pc == nil || pc.State == nil {
		return 0
	}
	return pc.State.RollbackFrom
}

// KeyEraID returns the Pulsar group-key lineage ID. Stable across
// every Reshare within a key era; bumps only at Reanchor.
func (pc *PulsarConfig) KeyEraID() uint64 {
	if pc == nil || pc.State == nil {
		return 0
	}
	return pc.State.KeyEraID
}

// Default values used by BuildActivationTranscript when a config does
// not set HashSuiteID / ImplementationVersion explicitly.
const (
	defaultHashSuiteID           = hash.DefaultID            // "Pulsar-SHA3"
	defaultImplementationVersion = "lss-pulsar-test-1.0"
)

// BuildActivationTranscript returns a fully-populated
// reshare.TranscriptInputs binding (chain_id, network_id, group_id,
// key_era_id, generations, epochs, sets, thresholds, group_pk_hash,
// nebula_root, hash_suite_id, implementation_version, variant) for
// the activation cert the new committee will threshold-sign under
// the unchanged GroupKey.
//
// Inputs:
//
//   - oldCfgs    — the configs that fed DynamicResharePulsar (their
//     KeyEraID, Generation, Threshold, Validators are read).
//   - newCfgs    — the configs returned by DynamicResharePulsar (their
//     Generation, Threshold, Validators are read).
//   - chainID, networkID, groupID — wire-level identifiers.
//   - groupPubKeyHash — 32-byte digest over the canonical (A, bTilde)
//     bytes of the persistent GroupKey. Caller computes once at era
//     bootstrap and reuses across every reshare in the era.
//   - nebulaRoot — Quasar frontier anchor; zero acceptable when the
//     consensus layer does not pin a frontier per resharing.
//   - hashSuiteID, implVersion — pinned profile and port identifiers;
//     empty values resolve to the package defaults
//     ("Pulsar-SHA3" and "lss-pulsar-test-1.0").
//   - variant — "refresh" or "reshare".
//   - suite — HashSuite for the validator-set hashes; nil = default.
//
// The returned transcript can be fed directly to
// reshare.ActivationMessage.SignableBytes(suite).
func BuildActivationTranscript(
	oldCfgs map[party.ID]*PulsarConfig,
	newCfgs map[party.ID]*PulsarConfig,
	chainID, networkID, groupID []byte,
	groupPubKeyHash [32]byte,
	nebulaRoot [32]byte,
	hashSuiteID, implVersion, variant string,
	suite hash.HashSuite,
) reshare.TranscriptInputs {
	if hashSuiteID == "" {
		hashSuiteID = defaultHashSuiteID
	}
	if implVersion == "" {
		implVersion = defaultImplementationVersion
	}

	// Pull old/new lineage from any one config — within an era / a
	// reshare batch the lineage is the same on every party.
	var (
		eraID         uint64
		oldGen, newGen uint64
		oldT, newT    int
		oldEpoch, newEpoch uint64
		oldKeys, newKeys [][]byte
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
	}
}

// Errors returned by the LSS-Pulsar adapter.
var (
	ErrPulsarNoOldConfigs        = errors.New("lss-pulsar: no old configurations provided")
	ErrPulsarInvalidThreshold    = errors.New("lss-pulsar: invalid new threshold")
	ErrPulsarKeyEraMismatch      = errors.New("lss-pulsar: old configs span multiple key eras")
	ErrPulsarGenerationMismatch  = errors.New("lss-pulsar: old configs span multiple generations")
	ErrPulsarGroupKeyMismatch    = errors.New("lss-pulsar: old configs disagree on GroupKey pointer")
	ErrPulsarInsufficientOldSet  = errors.New("lss-pulsar: insufficient old configs to form qualified set")
	ErrPulsarMissingShare        = errors.New("lss-pulsar: old config missing share")
	ErrPulsarKernelReshareFailed = errors.New("lss-pulsar: pulsar kernel reshare failed")
)

// DynamicResharePulsar performs LSS dynamic resharing on Pulsar
// configurations. Implements the LSS Section 4 lifecycle adapted for
// the Pulsar lattice setting:
//
//  1. Validate that all old configs agree on KeyEraID, Generation, and
//     GroupKey (they should — they came from the same era at the same
//     generation).
//  2. Reconstruct the in-process pulsar.KeyEra from the agreed-on
//     GroupKey + the union of old shares.
//  3. Call pulsar.KeyEra.Reshare with the new participant set + new
//     threshold. The kernel handles all lattice math: Reshare polynomial
//     sampling, Lagrange interpolation over the old qualified set,
//     Pedersen commits over R_q, Lambda recomputation, Seeds + MACKeys
//     regeneration.
//  4. Wrap the resulting EpochShareState into PulsarConfigs, one per
//     new party. Generation is bumped by the kernel; KeyEraID is
//     preserved; RollbackFrom is zero (forward transition).
//
// Adapter contract guarantees:
//
//   Preserved across the call: KeyEraID, GroupKey pointer, master
//     secret s (held only as shares; never reconstructed in this
//     process), and the persistent (A, bTilde) public key.
//
//   Changed across the call: Generation (incremented by 1), participant
//     set, threshold, share values, Lambdas, pairwise PRF Seeds, MAC
//     keys, transcript hash.
//
// Failure behavior: returns an error. The caller (LSS RollbackManager
// or Quasar consensus) decides whether to retry, rollback, or
// reanchor. The adapter does not silently fall back.
//
// rand defaults to crypto/rand.Reader. Tests pass a deterministic
// source for KAT replay.
func DynamicResharePulsar(
	oldConfigs map[party.ID]*PulsarConfig,
	newPartyIDs []party.ID,
	newThreshold int,
	_ *pool.Pool,
	rand io.Reader,
) (map[party.ID]*PulsarConfig, error) {
	if len(oldConfigs) == 0 {
		return nil, ErrPulsarNoOldConfigs
	}
	if newThreshold < 1 || newThreshold > len(newPartyIDs) {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrPulsarInvalidThreshold, newThreshold, len(newPartyIDs))
	}

	// 1. Validate consistency: all old configs must come from the same
	// key era at the same generation, with the same GroupKey pointer.
	var (
		refKeyEraID    uint64
		refGen         uint64
		refGroupKey    *pulsarThreshold.GroupKey
		refValidators  []string
		refThreshold   int
		first          = true
	)
	for _, cfg := range oldConfigs {
		if cfg == nil || cfg.State == nil {
			return nil, ErrPulsarMissingShare
		}
		if first {
			refKeyEraID = cfg.State.KeyEraID
			refGen = cfg.State.Generation
			refValidators = cfg.State.Validators
			refThreshold = cfg.State.Threshold
			first = false
			// Pull GroupKey from any one share — they all share the
			// same pointer within an era.
			for _, ks := range cfg.State.Shares {
				refGroupKey = ks.GroupKey
				break
			}
			continue
		}
		if cfg.State.KeyEraID != refKeyEraID {
			return nil, fmt.Errorf("%w: era %d != %d",
				ErrPulsarKeyEraMismatch, cfg.State.KeyEraID, refKeyEraID)
		}
		if cfg.State.Generation != refGen {
			return nil, fmt.Errorf("%w: gen %d != %d",
				ErrPulsarGenerationMismatch, cfg.State.Generation, refGen)
		}
		// Pointer-compare the GroupKey: within an era, every share
		// points to the same GroupKey instance. A different pointer
		// indicates corrupt input.
		for _, ks := range cfg.State.Shares {
			if ks.GroupKey != refGroupKey {
				return nil, ErrPulsarGroupKeyMismatch
			}
			break
		}
	}
	if refGroupKey == nil {
		return nil, ErrPulsarMissingShare
	}

	// 2. Pick a deterministic qualified-old-set of size t_old. Use the
	// first refThreshold validators in the canonical ordering.
	if refThreshold > len(oldConfigs) {
		return nil, fmt.Errorf("%w: have %d configs, need %d",
			ErrPulsarInsufficientOldSet, len(oldConfigs), refThreshold)
	}

	// 3. Reconstruct the pulsar.KeyEra from the union of old shares.
	// pulsar.KeyEra.Reshare expects a single in-process KeyEra holding
	// every old share — this is the trusted-collaborator path. In a
	// distributed deployment, the round-based protocol in
	// threshold/protocols/pulsar/ replaces this with per-party
	// computation; this adapter exists for the in-process / coordinator
	// path used by Quasar consensus orchestration.
	era := &keyera.KeyEra{
		EraID:        keyera.PulsarKeyEraID(refKeyEraID),
		GroupKey:     refGroupKey,
		GenesisEpoch: 0,
		State: &keyera.EpochShareState{
			KeyEraID:   refKeyEraID,
			Generation: refGen,
			Epoch:      0,
			Validators: refValidators,
			Threshold:  refThreshold,
			Shares:     make(map[string]*pulsarThreshold.KeyShare, len(oldConfigs)),
		},
	}
	for _, cfg := range oldConfigs {
		for v, ks := range cfg.State.Shares {
			era.State.Shares[v] = ks
		}
	}

	// 4. Call into the Pulsar kernel for all lattice math.
	newValidators := make([]string, len(newPartyIDs))
	for i, id := range newPartyIDs {
		newValidators[i] = string(id)
	}
	nextState, err := era.Reshare(newValidators, newThreshold, rand)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPulsarKernelReshareFailed, err)
	}

	// 5. Wrap each new share into a PulsarConfig, one per new party.
	// Generation was bumped inside the kernel; KeyEraID was preserved;
	// RollbackFrom is zero (forward transition).
	out := make(map[party.ID]*PulsarConfig, len(newPartyIDs))
	for _, id := range newPartyIDs {
		v := string(id)
		share, ok := nextState.Shares[v]
		if !ok {
			return nil, fmt.Errorf("lss-pulsar: kernel did not return share for %s", v)
		}
		// Per-party EpochShareState — slim, only this party's share.
		// All parties within the era share the same KeyEraID +
		// Generation + GroupKey pointer.
		perPartyState := &keyera.EpochShareState{
			KeyEraID:     nextState.KeyEraID,
			Generation:   nextState.Generation,
			RollbackFrom: 0,
			Epoch:        nextState.Epoch,
			Validators:   nextState.Validators,
			Threshold:    nextState.Threshold,
			Shares:       map[string]*pulsarThreshold.KeyShare{v: share},
		}
		out[id] = &PulsarConfig{
			State:   perPartyState,
			PartyID: id,
		}
	}
	return out, nil
}

// PulsarSnapshotManager is a per-Pulsar-era snapshot store. Mirrors the
// shape of LSS's RollbackManager but typed to PulsarConfig. Lives in
// the lss package so the unifying lifecycle abstraction stays in one
// place.
//
// Eventually the LSS RollbackManager should be generalized over a
// snapshot interface so PulsarConfig and ECDSA config.Config share one
// implementation. Until then, this is a parallel manager with the
// same API surface.
type PulsarSnapshotManager struct {
	mu             sync.RWMutex
	history        []*PulsarSnapshot
	maxGenerations int
	currentGen     uint64
}

// PulsarSnapshot is a point-in-time snapshot of a Pulsar key era's
// share state, suitable for rollback.
type PulsarSnapshot struct {
	KeyEraID   uint64
	Generation uint64
	State      *keyera.EpochShareState
	PartyIDs   []party.ID
	Threshold  int
}

// NewPulsarSnapshotManager creates a snapshot store keeping at most
// maxGenerations entries. Default 10 if maxGenerations < 1.
func NewPulsarSnapshotManager(maxGenerations int) *PulsarSnapshotManager {
	if maxGenerations < 1 {
		maxGenerations = 10
	}
	return &PulsarSnapshotManager{
		history:        make([]*PulsarSnapshot, 0, maxGenerations),
		maxGenerations: maxGenerations,
	}
}

// SaveSnapshot persists a per-generation snapshot. Should be called by
// the Signature Coordinator after a successful Reshare/Refresh activates
// (i.e. after the activation cert verifies under the unchanged
// GroupKey).
func (psm *PulsarSnapshotManager) SaveSnapshot(state *keyera.EpochShareState, partyIDs []party.ID) error {
	if state == nil {
		return errors.New("lss-pulsar: cannot save nil state")
	}
	psm.mu.Lock()
	defer psm.mu.Unlock()

	snap := &PulsarSnapshot{
		KeyEraID:   state.KeyEraID,
		Generation: state.Generation,
		State:      state,
		PartyIDs:   append([]party.ID(nil), partyIDs...),
		Threshold:  state.Threshold,
	}
	psm.history = append(psm.history, snap)
	if state.Generation > psm.currentGen {
		psm.currentGen = state.Generation
	}
	if len(psm.history) > psm.maxGenerations {
		psm.history = psm.history[len(psm.history)-psm.maxGenerations:]
	}
	return nil
}

// Rollback restores the share state at a target generation. Marks the
// restored state with RollbackFrom = currentGen and Generation =
// currentGen + 1, matching the LSS rollback lineage convention.
func (psm *PulsarSnapshotManager) Rollback(targetGeneration uint64) (*keyera.EpochShareState, error) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	if targetGeneration >= psm.currentGen {
		return nil, fmt.Errorf("lss-pulsar: cannot rollback to future generation %d (current: %d)",
			targetGeneration, psm.currentGen)
	}
	var target *PulsarSnapshot
	for i := len(psm.history) - 1; i >= 0; i-- {
		if psm.history[i].Generation == targetGeneration {
			target = psm.history[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("lss-pulsar: generation %d not in history", targetGeneration)
	}

	// Mark the rollback lineage — generation continues monotonically.
	restored := *target.State
	restored.Generation = psm.currentGen + 1
	restored.RollbackFrom = psm.currentGen
	psm.currentGen = restored.Generation
	return &restored, nil
}

// CurrentGeneration returns the most recently saved generation.
func (psm *PulsarSnapshotManager) CurrentGeneration() uint64 {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	return psm.currentGen
}

// HistorySize returns the number of snapshots currently retained.
func (psm *PulsarSnapshotManager) HistorySize() int {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	return len(psm.history)
}
