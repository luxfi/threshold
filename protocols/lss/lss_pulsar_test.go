// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package lss

import (
	"io"
	"testing"

	"github.com/luxfi/threshold/pkg/party"

	"github.com/luxfi/corona/keyera"
	pulsarThreshold "github.com/luxfi/corona/threshold"

	"github.com/zeebo/blake3"
)

// Acceptance tests for the LSS-Pulsar adapter, mirroring the 10 items
// in pulsar/DESIGN.md "Acceptance tests for lss_pulsar.go":
//
//   1. DynamicResharePulsar preserves GroupKey.
//   2. DynamicResharePulsar preserves KeyEraID.
//   3. Generation increments by one.
//   4. RollbackFrom is zero for ordinary forward transition.
//   5. t_old != t_new works.
//   6. old set != new set works.
//   7. regenerated shares can produce a valid Pulsar signature.
//   8. old shares are not needed after activation.
//   9. seeds/MAC keys are regenerated for exactly the new party set.
//  10. rollback restores the previous generation snapshot.

// bootstrapEra creates a fresh in-process key era for testing.
func bootstrapEra(t *testing.T, threshold int, validators []party.ID, seed string) *keyera.KeyEra {
	t.Helper()
	stringIDs := make([]string, len(validators))
	for i, v := range validators {
		stringIDs[i] = string(v)
	}
	era, err := keyera.BootstrapTrustedDealer(threshold, stringIDs, 0, 1, deterministicRand(seed))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return era
}

// eraToConfigs splits a KeyEra into per-party PulsarConfigs, the input
// shape DynamicResharePulsar consumes.
func eraToConfigs(era *keyera.KeyEra) map[party.ID]*PulsarConfig {
	out := make(map[party.ID]*PulsarConfig, len(era.State.Shares))
	for vStr, share := range era.State.Shares {
		id := party.ID(vStr)
		perParty := &keyera.EpochShareState{
			KeyEraID:     era.State.KeyEraID,
			Generation:   era.State.Generation,
			RollbackFrom: era.State.RollbackFrom,
			Epoch:        era.State.Epoch,
			Validators:   era.State.Validators,
			Threshold:    era.State.Threshold,
			Shares:       map[string]*pulsarThreshold.KeyShare{vStr: share},
		}
		out[id] = &PulsarConfig{State: perParty, PartyID: id}
	}
	return out
}

// Test 1: DynamicResharePulsar preserves GroupKey.
// Test 2: DynamicResharePulsar preserves KeyEraID.
// Test 3: Generation increments by one.
// Test 4: RollbackFrom is zero for ordinary forward transition.
func TestPulsarAdapter_PreservesLineage(t *testing.T) {
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapEra(t, 3, oldSet, "preserves-lineage-genesis")
	gkBefore := era.GroupKey
	eraIDBefore := era.State.KeyEraID
	genBefore := era.State.Generation

	oldCfgs := eraToConfigs(era)

	newCfgs, err := DynamicResharePulsar(oldCfgs, oldSet, 3, nil, deterministicRand("preserves-lineage-reshare"))
	if err != nil {
		t.Fatalf("DynamicResharePulsar: %v", err)
	}
	if len(newCfgs) != len(oldSet) {
		t.Fatalf("output config count: want %d got %d", len(oldSet), len(newCfgs))
	}

	for id, cfg := range newCfgs {
		share, ok := cfg.State.Shares[string(id)]
		if !ok {
			t.Fatalf("missing share for %s", id)
		}
		// Test 1: GroupKey pointer preserved.
		if share.GroupKey != gkBefore {
			t.Errorf("party %s: GroupKey pointer changed across reshare", id)
		}
		// Test 2: KeyEraID preserved.
		if cfg.KeyEraID() != eraIDBefore {
			t.Errorf("party %s: KeyEraID: want %d got %d", id, eraIDBefore, cfg.KeyEraID())
		}
		// Test 3: Generation incremented by exactly one.
		if cfg.Generation() != genBefore+1 {
			t.Errorf("party %s: Generation: want %d got %d", id, genBefore+1, cfg.Generation())
		}
		// Test 4: RollbackFrom is zero on forward transition.
		if cfg.RollbackFrom() != 0 {
			t.Errorf("party %s: RollbackFrom on forward transition: want 0 got %d", id, cfg.RollbackFrom())
		}
	}
}

// Test 5: t_old != t_new works.
// Test 6: old set != new set works.
func TestPulsarAdapter_SetAndThresholdRotation(t *testing.T) {
	oldSet := []party.ID{"v1", "v2", "v3"}
	era := bootstrapEra(t, 3, oldSet, "rotation-genesis")
	oldCfgs := eraToConfigs(era)

	newSet := []party.ID{"v4", "v5", "v6", "v7", "v8"}
	const tNew = 5
	newCfgs, err := DynamicResharePulsar(oldCfgs, newSet, tNew, nil, deterministicRand("rotation-reshare"))
	if err != nil {
		t.Fatalf("DynamicResharePulsar (rotation): %v", err)
	}
	if len(newCfgs) != len(newSet) {
		t.Fatalf("rotation: output count want %d got %d", len(newSet), len(newCfgs))
	}
	for _, id := range newSet {
		cfg, ok := newCfgs[id]
		if !ok {
			t.Errorf("missing config for new party %s", id)
			continue
		}
		if cfg.State.Threshold != tNew {
			t.Errorf("party %s: threshold: want %d got %d", id, tNew, cfg.State.Threshold)
		}
	}
	for _, oldID := range oldSet {
		if _, ok := newCfgs[oldID]; ok {
			t.Errorf("old party %s should not be in new config set after disjoint rotation", oldID)
		}
	}
}

// Test 7: regenerated shares can produce a valid Pulsar signature.
// Test 8: signing under the new committee verifies against the unchanged
// GroupKey, demonstrating that old shares are not needed after activation.
func TestPulsarAdapter_NewCommitteeSigns(t *testing.T) {
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapEra(t, 3, oldSet, "signs-genesis")
	gkBefore := era.GroupKey
	oldCfgs := eraToConfigs(era)

	newSet := []party.ID{"x", "y", "z"}
	newCfgs, err := DynamicResharePulsar(oldCfgs, newSet, 3, nil, deterministicRand("signs-reshare"))
	if err != nil {
		t.Fatalf("DynamicResharePulsar: %v", err)
	}

	signersByID := make(map[party.ID]*pulsarThreshold.Signer, len(newSet))
	for _, id := range newSet {
		share := newCfgs[id].State.Shares[string(id)]
		signersByID[id] = pulsarThreshold.NewSigner(share)
	}

	signerIndices := make([]int, 0, len(newSet))
	for _, id := range newSet {
		signerIndices = append(signerIndices, newCfgs[id].State.Shares[string(id)].Index)
	}
	const sessionID = 42
	prfKey := []byte("lss-pulsar-test-prf-key-32-byte!")[:32]
	const message = "lss-pulsar-test-message"

	round1 := make(map[int]*pulsarThreshold.Round1Data, len(newSet))
	for _, id := range newSet {
		idx := newCfgs[id].State.Shares[string(id)].Index
		// corona v0.8.0: Signer.Round1 now returns (*Round1Data, error)
		// — it can refuse a degenerate session instead of panicking.
		r1, err := signersByID[id].Round1(sessionID, prfKey, signerIndices)
		if err != nil {
			t.Fatalf("Round1 for %s: %v", id, err)
		}
		round1[idx] = r1
	}
	round2 := make(map[int]*pulsarThreshold.Round2Data, len(newSet))
	for _, id := range newSet {
		r2, err := signersByID[id].Round2(sessionID, message, prfKey, signerIndices, round1)
		if err != nil {
			t.Fatalf("Round2 for %s: %v", id, err)
		}
		round2[r2.PartyID] = r2
	}
	sig, err := signersByID[newSet[0]].Finalize(round2)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !pulsarThreshold.Verify(gkBefore, message, sig) {
		t.Fatal("new-committee signature failed to verify under UNCHANGED GroupKey")
	}
}

// Test 9: seeds/MAC keys are regenerated for exactly the new party set.
// We confirm: each new share has Seeds and MACKeys keyed by the new
// committee's index space (0..K-1), and the bytes differ from the old
// shares.
func TestPulsarAdapter_PairwiseMaterialRegenerated(t *testing.T) {
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapEra(t, 3, oldSet, "pairwise-genesis")
	oldCfgs := eraToConfigs(era)

	// Snapshot one old share's seeds[0][0] so we can compare.
	var oldSeed0 []byte
	for _, cfg := range oldCfgs {
		for _, share := range cfg.State.Shares {
			oldSeed0 = append([]byte(nil), share.Seeds[0][0]...)
			break
		}
		break
	}

	newSet := []party.ID{"x", "y", "z"}
	newCfgs, err := DynamicResharePulsar(oldCfgs, newSet, 3, nil, deterministicRand("pairwise-reshare"))
	if err != nil {
		t.Fatalf("DynamicResharePulsar: %v", err)
	}

	for _, id := range newSet {
		share := newCfgs[id].State.Shares[string(id)]
		// Seeds keyed by 0..K-1 for the new committee.
		if got := len(share.Seeds); got != len(newSet) {
			t.Errorf("party %s: Seeds outer dimension: want %d got %d", id, len(newSet), got)
		}
		for i := 0; i < len(newSet); i++ {
			if got := len(share.Seeds[i]); got != len(newSet) {
				t.Errorf("party %s: Seeds[%d] dimension: want %d got %d", id, i, len(newSet), got)
			}
		}
		// MACKeys keyed by 0..K-1 \ {own index}.
		if got, want := len(share.MACKeys), len(newSet)-1; got != want {
			t.Errorf("party %s: MACKeys size: want %d got %d", id, want, got)
		}
		// Confirm the bytes differ from the old committee's seeds.
		newSeed0 := share.Seeds[0][0]
		if equalBytes(oldSeed0, newSeed0) {
			t.Errorf("party %s: pairwise material was not regenerated (seed[0][0] identical to old)", id)
		}
		break // one party is enough for the byte-equality check
	}
}

// Test 10: rollback restores the previous generation snapshot.
func TestPulsarAdapter_RollbackRestoresGeneration(t *testing.T) {
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapEra(t, 3, oldSet, "rollback-genesis")
	oldCfgs := eraToConfigs(era)

	mgr := NewPulsarSnapshotManager(5)

	// Save genesis snapshot (gen 0).
	if err := mgr.SaveSnapshot(era.State, oldSet); err != nil {
		t.Fatalf("SaveSnapshot gen 0: %v", err)
	}

	// Forward transition to gen 1.
	gen1Cfgs, err := DynamicResharePulsar(oldCfgs, oldSet, 3, nil, deterministicRand("rollback-reshare-1"))
	if err != nil {
		t.Fatalf("DynamicResharePulsar gen 1: %v", err)
	}
	// Assemble gen 1's full state for snapshot.
	gen1State := mergeConfigs(gen1Cfgs, oldSet)
	if err := mgr.SaveSnapshot(gen1State, oldSet); err != nil {
		t.Fatalf("SaveSnapshot gen 1: %v", err)
	}
	if got := mgr.CurrentGeneration(); got != 1 {
		t.Fatalf("current generation after gen 1 save: want 1 got %d", got)
	}

	// Rollback to gen 0. Restored state's Generation jumps to 2 (current+1)
	// and RollbackFrom == 1 (the gen we reverted from).
	restored, err := mgr.Rollback(0)
	if err != nil {
		t.Fatalf("Rollback to 0: %v", err)
	}
	if restored.Generation != 2 {
		t.Errorf("restored.Generation: want 2 got %d", restored.Generation)
	}
	if restored.RollbackFrom != 1 {
		t.Errorf("restored.RollbackFrom: want 1 got %d", restored.RollbackFrom)
	}
	if restored.KeyEraID != era.State.KeyEraID {
		t.Errorf("restored.KeyEraID: want %d got %d", era.State.KeyEraID, restored.KeyEraID)
	}
	if restored.Threshold != era.State.Threshold {
		t.Errorf("restored.Threshold: want %d got %d", era.State.Threshold, restored.Threshold)
	}
}

// TestPulsarAdapter_InvalidInputs covers the error surface.
func TestPulsarAdapter_InvalidInputs(t *testing.T) {
	if _, err := DynamicResharePulsar(nil, nil, 0, nil, nil); err == nil {
		t.Error("expected error for empty old configs")
	}
	if _, err := DynamicResharePulsar(map[party.ID]*PulsarConfig{}, nil, 0, nil, nil); err == nil {
		t.Error("expected error for empty old configs")
	}
	era := bootstrapEra(t, 3, []party.ID{"a", "b", "c"}, "errs-bootstrap")
	cfgs := eraToConfigs(era)
	if _, err := DynamicResharePulsar(cfgs, []party.ID{"x", "y"}, 0, nil, nil); err == nil {
		t.Error("expected error for threshold < 1")
	}
	if _, err := DynamicResharePulsar(cfgs, []party.ID{"x", "y"}, 3, nil, nil); err == nil {
		t.Error("expected error for threshold > new-set-size")
	}
}

// mergeConfigs is a test helper that gathers per-party PulsarConfigs
// back into a single EpochShareState for snapshot purposes.
func mergeConfigs(cfgs map[party.ID]*PulsarConfig, ids []party.ID) *keyera.EpochShareState {
	if len(cfgs) == 0 {
		return nil
	}
	var ref *keyera.EpochShareState
	for _, c := range cfgs {
		ref = c.State
		break
	}
	merged := &keyera.EpochShareState{
		KeyEraID:     ref.KeyEraID,
		Generation:   ref.Generation,
		RollbackFrom: ref.RollbackFrom,
		Epoch:        ref.Epoch,
		Validators:   ref.Validators,
		Threshold:    ref.Threshold,
		Shares:       make(map[string]*pulsarThreshold.KeyShare, len(cfgs)),
	}
	for _, id := range ids {
		v := string(id)
		if cfg, ok := cfgs[id]; ok {
			if share, ok := cfg.State.Shares[v]; ok {
				merged.Shares[v] = share
			}
		}
	}
	return merged
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// deterministicRand returns an unbounded byte stream from a seed
// string for KAT-replay.
func deterministicRand(seed string) io.Reader {
	h := blake3.New()
	_, _ = h.Write([]byte("lss.pulsar.test.rng.v1"))
	_, _ = h.Write([]byte(seed))
	return h.Digest()
}

// TestPulsarAdapter_BuildActivationTranscript_NewFields covers the
// Bucket B addition: NebulaRoot, HashSuiteID, ImplementationVersion
// MUST flow through to the resulting TranscriptInputs.
func TestPulsarAdapter_BuildActivationTranscript_NewFields(t *testing.T) {
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapEra(t, 3, oldSet, "build-transcript-genesis")
	oldCfgs := eraToConfigs(era)

	newCfgs, err := DynamicResharePulsar(oldCfgs, oldSet, 3, nil, deterministicRand("build-transcript-reshare"))
	if err != nil {
		t.Fatalf("DynamicResharePulsar: %v", err)
	}

	nebulaRoot := [32]byte{0xAA, 0xBB, 0xCC, 0xDD}
	groupPubKeyHash := [32]byte{0x11, 0x22, 0x33, 0x44}

	got := BuildActivationTranscript(
		oldCfgs, newCfgs,
		[]byte("lux-mainnet"), []byte("network-1"), []byte("group-0"),
		groupPubKeyHash,
		nebulaRoot,
		"", "", // intentionally empty so defaults kick in
		"reshare",
		nil,
	)

	if got.NebulaRoot != nebulaRoot {
		t.Errorf("NebulaRoot not threaded through: want %x got %x", nebulaRoot, got.NebulaRoot)
	}
	if got.HashSuiteID != "Corona-SHA3" {
		t.Errorf("HashSuiteID default: want %q got %q", "Corona-SHA3", got.HashSuiteID)
	}
	if got.ImplementationVersion != "lss-pulsar-test-1.0" {
		t.Errorf("ImplementationVersion default: want %q got %q", "lss-pulsar-test-1.0", got.ImplementationVersion)
	}
	if got.GroupPublicKeyHash != groupPubKeyHash {
		t.Errorf("GroupPublicKeyHash not threaded through")
	}
	if got.Variant != "reshare" {
		t.Errorf("Variant: want reshare got %q", got.Variant)
	}
	// Lineage fields propagate from the configs.
	if got.KeyEraID != era.State.KeyEraID {
		t.Errorf("KeyEraID: want %d got %d", era.State.KeyEraID, got.KeyEraID)
	}
	if got.NewGeneration != era.State.Generation+1 {
		t.Errorf("NewGeneration: want %d got %d", era.State.Generation+1, got.NewGeneration)
	}

	// Override defaults: ensure non-empty values pass through.
	got2 := BuildActivationTranscript(
		oldCfgs, newCfgs,
		[]byte("lux-mainnet"), nil, []byte("group-0"),
		groupPubKeyHash,
		nebulaRoot,
		"Pulsar-BLAKE3", "lss-pulsar-prod-2.0",
		"refresh",
		nil,
	)
	if got2.HashSuiteID != "Pulsar-BLAKE3" {
		t.Errorf("HashSuiteID override: want Pulsar-BLAKE3 got %q", got2.HashSuiteID)
	}
	if got2.ImplementationVersion != "lss-pulsar-prod-2.0" {
		t.Errorf("ImplementationVersion override: want lss-pulsar-prod-2.0 got %q", got2.ImplementationVersion)
	}
	if got2.Variant != "refresh" {
		t.Errorf("Variant override: want refresh got %q", got2.Variant)
	}
}
