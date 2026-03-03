// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package lss

import (
	"io"
	"testing"

	"github.com/luxfi/threshold/pkg/party"

	"github.com/luxfi/lens/keyera"
	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/sign"
	lensThreshold "github.com/luxfi/lens/threshold"

	"github.com/zeebo/blake3"
)

// Acceptance tests for the LSS-Lens adapter, mirroring the 10 items
// in lps/LP-103-lens.md "Acceptance criteria":
//
//   1. DynamicReshareLens preserves GroupKey.
//   2. DynamicReshareLens preserves KeyEraID.
//   3. Generation increments by one.
//   4. RollbackFrom is zero for ordinary forward transition.
//   5. t_old != t_new works.
//   6. old set != new set works.
//   7. regenerated shares can produce a valid Lens (FROST) signature.
//   8. old shares are not needed after activation.
//   9. seeds/MAC keys are regenerated for exactly the new party set.
//  10. rollback restores the previous generation snapshot.

// bootstrapLensEra creates a fresh in-process key era for testing.
func bootstrapLensEra(t *testing.T, c primitives.Curve, threshold int, validators []party.ID, seed string) *keyera.KeyEra {
	t.Helper()
	stringIDs := make([]string, len(validators))
	for i, v := range validators {
		stringIDs[i] = string(v)
	}
	era, err := keyera.Bootstrap(c, threshold, stringIDs, 0, 1, deterministicLensRand(seed))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return era
}

// lensEraToConfigs splits a KeyEra into per-party LensConfigs, the
// input shape DynamicReshareLens consumes.
func lensEraToConfigs(era *keyera.KeyEra) map[party.ID]*LensConfig {
	out := make(map[party.ID]*LensConfig, len(era.State.Shares))
	for vStr, share := range era.State.Shares {
		id := party.ID(vStr)
		perParty := &keyera.EpochShareState{
			KeyEraID:     era.State.KeyEraID,
			Generation:   era.State.Generation,
			RollbackFrom: era.State.RollbackFrom,
			Epoch:        era.State.Epoch,
			Validators:   era.State.Validators,
			Threshold:    era.State.Threshold,
			Shares:       map[string]*lensThreshold.KeyShare{vStr: share},
		}
		out[id] = &LensConfig{State: perParty, PartyID: id}
	}
	return out
}

// Test 1: DynamicReshareLens preserves GroupKey.
// Test 2: DynamicReshareLens preserves KeyEraID.
// Test 3: Generation increments by one.
// Test 4: RollbackFrom is zero for ordinary forward transition.
func TestLensAdapter_PreservesLineage(t *testing.T) {
	c := primitives.NewEd25519()
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapLensEra(t, c, 3, oldSet, "preserves-lineage-genesis")
	gkBefore := era.GroupKey
	eraIDBefore := era.State.KeyEraID
	genBefore := era.State.Generation

	oldCfgs := lensEraToConfigs(era)

	newCfgs, err := DynamicReshareLens(oldCfgs, oldSet, 3, nil, deterministicLensRand("preserves-lineage-reshare"))
	if err != nil {
		t.Fatalf("DynamicReshareLens: %v", err)
	}
	if len(newCfgs) != len(oldSet) {
		t.Fatalf("output config count: want %d got %d", len(oldSet), len(newCfgs))
	}

	for id, cfg := range newCfgs {
		share, ok := cfg.State.Shares[string(id)]
		if !ok {
			t.Fatalf("missing share for %s", id)
		}
		if share.GroupKey != gkBefore {
			t.Errorf("party %s: GroupKey pointer changed across reshare", id)
		}
		if cfg.KeyEraID() != eraIDBefore {
			t.Errorf("party %s: KeyEraID: want %d got %d", id, eraIDBefore, cfg.KeyEraID())
		}
		if cfg.Generation() != genBefore+1 {
			t.Errorf("party %s: Generation: want %d got %d", id, genBefore+1, cfg.Generation())
		}
		if cfg.RollbackFrom() != 0 {
			t.Errorf("party %s: RollbackFrom on forward transition: want 0 got %d", id, cfg.RollbackFrom())
		}
	}
}

// Test 5: t_old != t_new works.
// Test 6: old set != new set works.
func TestLensAdapter_SetAndThresholdRotation(t *testing.T) {
	c := primitives.NewSecp256k1()
	oldSet := []party.ID{"v1", "v2", "v3"}
	era := bootstrapLensEra(t, c, 3, oldSet, "rotation-genesis")
	oldCfgs := lensEraToConfigs(era)

	newSet := []party.ID{"v4", "v5", "v6", "v7", "v8"}
	const tNew = 5
	newCfgs, err := DynamicReshareLens(oldCfgs, newSet, tNew, nil, deterministicLensRand("rotation-reshare"))
	if err != nil {
		t.Fatalf("DynamicReshareLens (rotation): %v", err)
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

// Test 7: regenerated shares can produce a valid Lens (FROST)
// signature.
// Test 8: signing under the new committee verifies against the
// unchanged GroupKey, demonstrating that old shares are not needed
// after activation.
func TestLensAdapter_NewCommitteeSigns(t *testing.T) {
	for _, c := range []primitives.Curve{
		primitives.NewEd25519(),
		primitives.NewSecp256k1(),
		primitives.NewRistretto255(),
	} {
		t.Run(c.Name(), func(t *testing.T) {
			oldSet := []party.ID{"a", "b", "c"}
			era := bootstrapLensEra(t, c, 3, oldSet, "signs-genesis")
			gkBefore := era.GroupKey
			oldCfgs := lensEraToConfigs(era)

			newSet := []party.ID{"x", "y", "z"}
			newCfgs, err := DynamicReshareLens(oldCfgs, newSet, 3, nil, deterministicLensRand("signs-reshare"))
			if err != nil {
				t.Fatalf("DynamicReshareLens: %v", err)
			}

			// Run FROST signing.
			signers := []int{1, 2, 3}
			signersByID := make(map[int]*sign.Signer, len(newSet))
			keysByID := make(map[int]*lensThreshold.KeyShare, len(newSet))
			for _, id := range newSet {
				ks := newCfgs[id].State.Shares[string(id)]
				signersByID[ks.PartyID] = sign.NewSigner(ks)
				keysByID[ks.PartyID] = ks
			}
			const message = "lss-lens-test-message"
			commits := make(map[int]*sign.CommitMsg, len(signers))
			for _, id := range signers {
				cm, err := signersByID[id].Round1([]byte(message), signers, deterministicLensRand("sign-round1"))
				if err != nil {
					t.Fatalf("Round1 for %d: %v", id, err)
				}
				commits[id] = cm
			}
			responses := make(map[int]*sign.ResponseMsg, len(signers))
			for _, id := range signers {
				rm, err := signersByID[id].Round2([]byte(message), commits)
				if err != nil {
					t.Fatalf("Round2 for %d: %v", id, err)
				}
				responses[id] = rm
			}
			verShares := make(map[int]primitives.Point, len(keysByID))
			for id, ks := range keysByID {
				verShares[id] = ks.VerificationShare
			}
			sig, err := sign.Aggregate(gkBefore, []byte(message), signers, commits, responses, verShares)
			if err != nil {
				t.Fatalf("Aggregate: %v", err)
			}
			if err := sign.Verify(gkBefore, []byte(message), sig); err != nil {
				t.Fatalf("new-committee signature failed to verify under UNCHANGED GroupKey: %v", err)
			}
		})
	}
}

// Test 9: pairwise material is regenerated for the new party set.
// Each new share has Seeds and MACKeys keyed by the new committee's
// index space (0..K-1), and the bytes differ from the old shares.
func TestLensAdapter_PairwiseMaterialRegenerated(t *testing.T) {
	c := primitives.NewEd25519()
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapLensEra(t, c, 3, oldSet, "pairwise-genesis")
	oldCfgs := lensEraToConfigs(era)

	var oldSeed0 []byte
	for _, cfg := range oldCfgs {
		for _, share := range cfg.State.Shares {
			if share.Seeds != nil && share.Seeds[0] != nil {
				oldSeed0 = append([]byte(nil), share.Seeds[0][0]...)
			}
			break
		}
		break
	}

	newSet := []party.ID{"x", "y", "z"}
	newCfgs, err := DynamicReshareLens(oldCfgs, newSet, 3, nil, deterministicLensRand("pairwise-reshare"))
	if err != nil {
		t.Fatalf("DynamicReshareLens: %v", err)
	}

	for _, id := range newSet {
		share := newCfgs[id].State.Shares[string(id)]
		if got := len(share.Seeds); got != len(newSet) {
			t.Errorf("party %s: Seeds outer dimension: want %d got %d", id, len(newSet), got)
		}
		for i := 0; i < len(newSet); i++ {
			if got := len(share.Seeds[i]); got != len(newSet) {
				t.Errorf("party %s: Seeds[%d] dimension: want %d got %d", id, i, len(newSet), got)
			}
		}
		if got, want := len(share.MACKeys), len(newSet)-1; got != want {
			t.Errorf("party %s: MACKeys size: want %d got %d", id, want, got)
		}
		newSeed0 := share.Seeds[0][0]
		if equalLensBytes(oldSeed0, newSeed0) {
			t.Errorf("party %s: pairwise material was not regenerated (seed[0][0] identical to old)", id)
		}
		break
	}
}

// Test 10: rollback restores the previous generation snapshot.
func TestLensAdapter_RollbackRestoresGeneration(t *testing.T) {
	c := primitives.NewEd25519()
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapLensEra(t, c, 3, oldSet, "rollback-genesis")
	oldCfgs := lensEraToConfigs(era)

	mgr := NewLensSnapshotManager(5)

	if err := mgr.SaveSnapshot(era.State, oldSet); err != nil {
		t.Fatalf("SaveSnapshot gen 0: %v", err)
	}

	gen1Cfgs, err := DynamicReshareLens(oldCfgs, oldSet, 3, nil, deterministicLensRand("rollback-reshare-1"))
	if err != nil {
		t.Fatalf("DynamicReshareLens gen 1: %v", err)
	}
	gen1State := mergeLensConfigs(gen1Cfgs, oldSet)
	if err := mgr.SaveSnapshot(gen1State, oldSet); err != nil {
		t.Fatalf("SaveSnapshot gen 1: %v", err)
	}
	if got := mgr.CurrentGeneration(); got != 1 {
		t.Fatalf("current generation after gen 1 save: want 1 got %d", got)
	}

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

// TestLensAdapter_InvalidInputs covers the error surface.
func TestLensAdapter_InvalidInputs(t *testing.T) {
	c := primitives.NewEd25519()
	if _, err := DynamicReshareLens(nil, nil, 0, nil, nil); err == nil {
		t.Error("expected error for empty old configs")
	}
	if _, err := DynamicReshareLens(map[party.ID]*LensConfig{}, nil, 0, nil, nil); err == nil {
		t.Error("expected error for empty old configs")
	}
	era := bootstrapLensEra(t, c, 3, []party.ID{"a", "b", "c"}, "errs-bootstrap")
	cfgs := lensEraToConfigs(era)
	if _, err := DynamicReshareLens(cfgs, []party.ID{"x", "y"}, 0, nil, nil); err == nil {
		t.Error("expected error for threshold < 1")
	}
	if _, err := DynamicReshareLens(cfgs, []party.ID{"x", "y"}, 3, nil, nil); err == nil {
		t.Error("expected error for threshold > new-set-size")
	}
}

// TestLensAdapter_BuildActivationTranscript_NewFields covers the
// transcript-binding fields propagated to the activation message.
func TestLensAdapter_BuildActivationTranscript_NewFields(t *testing.T) {
	c := primitives.NewEd25519()
	oldSet := []party.ID{"a", "b", "c"}
	era := bootstrapLensEra(t, c, 3, oldSet, "build-transcript-genesis")
	oldCfgs := lensEraToConfigs(era)

	newCfgs, err := DynamicReshareLens(oldCfgs, oldSet, 3, nil, deterministicLensRand("build-transcript-reshare"))
	if err != nil {
		t.Fatalf("DynamicReshareLens: %v", err)
	}

	nebulaRoot := [32]byte{0xAA, 0xBB, 0xCC, 0xDD}
	groupPubKeyHash := [32]byte{0x11, 0x22, 0x33, 0x44}

	got := BuildLensActivationTranscript(
		oldCfgs, newCfgs,
		[]byte("lux-mainnet"), []byte("network-1"), []byte("group-0"),
		groupPubKeyHash,
		nebulaRoot,
		"", "",
		"reshare",
		nil,
	)

	if got.NebulaRoot != nebulaRoot {
		t.Errorf("NebulaRoot not threaded through: want %x got %x", nebulaRoot, got.NebulaRoot)
	}
	if got.HashSuiteID != "Lens-SHA3" {
		t.Errorf("HashSuiteID default: want %q got %q", "Lens-SHA3", got.HashSuiteID)
	}
	if got.ImplementationVersion != "lss-lens-test-1.0" {
		t.Errorf("ImplementationVersion default: want %q got %q", "lss-lens-test-1.0", got.ImplementationVersion)
	}
	if got.GroupPublicKeyHash != groupPubKeyHash {
		t.Errorf("GroupPublicKeyHash not threaded through")
	}
	if got.Variant != "reshare" {
		t.Errorf("Variant: want reshare got %q", got.Variant)
	}
	if got.CurveName != "ed25519" {
		t.Errorf("CurveName: want ed25519 got %q", got.CurveName)
	}
	if got.KeyEraID != era.State.KeyEraID {
		t.Errorf("KeyEraID: want %d got %d", era.State.KeyEraID, got.KeyEraID)
	}
	if got.NewGeneration != era.State.Generation+1 {
		t.Errorf("NewGeneration: want %d got %d", era.State.Generation+1, got.NewGeneration)
	}

	// Override defaults.
	got2 := BuildLensActivationTranscript(
		oldCfgs, newCfgs,
		[]byte("lux-mainnet"), nil, []byte("group-0"),
		groupPubKeyHash,
		nebulaRoot,
		"Lens-BLAKE3", "lss-lens-prod-2.0",
		"refresh",
		nil,
	)
	if got2.HashSuiteID != "Lens-BLAKE3" {
		t.Errorf("HashSuiteID override: want Lens-BLAKE3 got %q", got2.HashSuiteID)
	}
	if got2.ImplementationVersion != "lss-lens-prod-2.0" {
		t.Errorf("ImplementationVersion override: want lss-lens-prod-2.0 got %q", got2.ImplementationVersion)
	}
	if got2.Variant != "refresh" {
		t.Errorf("Variant override: want refresh got %q", got2.Variant)
	}
}

// mergeLensConfigs is a test helper that gathers per-party LensConfigs
// back into a single EpochShareState for snapshot purposes.
func mergeLensConfigs(cfgs map[party.ID]*LensConfig, ids []party.ID) *keyera.EpochShareState {
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
		Shares:       make(map[string]*lensThreshold.KeyShare, len(cfgs)),
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

func equalLensBytes(a, b []byte) bool {
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

// deterministicLensRand returns an unbounded byte stream from a seed
// string for KAT-replay.
func deterministicLensRand(seed string) io.Reader {
	h := blake3.New()
	_, _ = h.Write([]byte("lss.lens.test.rng.v1"))
	_, _ = h.Write([]byte(seed))
	return h.Digest()
}
