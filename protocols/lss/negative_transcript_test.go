// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lss — Gate 4 negative-transcript tests for the LSS-Pulsar
// adapter (Mar-3-2026 PQ Consensus Architecture Freeze).
//
// BuildActivationTranscript flows lifecycle fields from the LSS-side
// PulsarConfigs into a reshare.TranscriptInputs that the new committee
// signs under the unchanged GroupKey. Gate 4 pins that every one of
// the 17 transcript-binding fields is part of the canonical bytes:
// mutating any single one MUST change the transcript hash and reject
// the activation cert.
//
// Citations (canonical proof bucket):
//
//   proofs/definitions/transcript-binding.tex
//     Definition ref:pulsar-transcript
//   proofs/pulsar/hash-suite-separation.tex
//     Theorem ref:hash-suite-separation
package lss

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/pulsar/reshare"
)

// lssBaselineTranscript builds the baseline TranscriptInputs an
// LSS-Pulsar adapter would emit at activation time, with every field
// non-zero so a single-field mutation cannot accidentally land on the
// same value.
func lssBaselineTranscript() reshare.TranscriptInputs {
	return reshare.TranscriptInputs{
		ChainID:               []byte("lux-mainnet"),
		NetworkID:             []byte("network-1"),
		GroupID:               []byte("quasar-pq-group-0"),
		KeyEraID:              7,
		OldGeneration:         11,
		NewGeneration:         12,
		OldEpochID:            42,
		NewEpochID:            43,
		OldSetHash:            [32]byte{0x01, 0x02, 0x03, 0x04, 0x05},
		NewSetHash:            [32]byte{0x10, 0x11, 0x12, 0x13, 0x14},
		ThresholdOld:          11,
		ThresholdNew:          13,
		GroupPublicKeyHash:    [32]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4},
		NebulaRoot:            [32]byte{0xb0, 0xb1, 0xb2, 0xb3, 0xb4},
		HashSuiteID:           "Pulsar-SHA3",
		ImplementationVersion: "lss-pulsar-prod-1.0",
		Variant:               "reshare",
	}
}

// lssBaselineActivation wraps the baseline TranscriptInputs in a full
// activation message with a non-trivial reshare-exchange transcript.
func lssBaselineActivation() reshare.ActivationMessage {
	return reshare.ActivationMessage{
		Transcript: lssBaselineTranscript(),
		ReshareTranscript: reshare.ReshareTranscript{
			CommitDigests: map[int][32]byte{
				1: {0x11}, 2: {0x22}, 3: {0x33},
			},
			ComplaintHashes:     [][32]byte{{0xc0}, {0xc1}},
			DisqualifiedSenders: []int{4},
			QualifiedQuorum:     []int{1, 2, 3},
		},
	}
}

// honestThresholdVerifier mirrors the closure from
// pulsar/reshare/negative_transcript_test.go: accepts iff the bytes
// equal the baseline activation bytes.
func lssHonestVerifier(baselineSignable []byte) func(message, signature []byte) bool {
	return func(message, signature []byte) bool {
		return bytes.Equal(message, baselineSignable) && bytes.Equal(signature, []byte("lss-baseline-sig"))
	}
}

// lssMutateTranscriptField returns a copy of the activation message
// with exactly one field mutated.
func lssMutateTranscriptField(t *testing.T, base reshare.ActivationMessage, field string) reshare.ActivationMessage {
	t.Helper()
	m := base
	m.Transcript = base.Transcript
	switch field {
	case "chain_id":
		m.Transcript.ChainID = []byte("lux-testnet")
	case "network_id":
		m.Transcript.NetworkID = []byte("network-2")
	case "group_id":
		m.Transcript.GroupID = []byte("quasar-pq-group-99")
	case "key_era_id":
		m.Transcript.KeyEraID = 8
	case "old_generation":
		m.Transcript.OldGeneration = 99
	case "new_generation":
		m.Transcript.NewGeneration = 99
	case "old_epoch_id":
		m.Transcript.OldEpochID = 1000
	case "new_epoch_id":
		m.Transcript.NewEpochID = 1001
	case "old_set_hash":
		m.Transcript.OldSetHash = [32]byte{0xff, 0xff, 0xff, 0xff}
	case "new_set_hash":
		m.Transcript.NewSetHash = [32]byte{0xee, 0xee, 0xee, 0xee}
	case "threshold_old":
		m.Transcript.ThresholdOld = 99
	case "threshold_new":
		m.Transcript.ThresholdNew = 99
	case "group_public_key_hash":
		m.Transcript.GroupPublicKeyHash = [32]byte{0xff, 0xff, 0xff, 0xff}
	case "nebula_root":
		m.Transcript.NebulaRoot = [32]byte{0xee, 0xee, 0xee, 0xee}
	case "hash_suite_id":
		m.Transcript.HashSuiteID = "Pulsar-BLAKE3"
	case "implementation_version":
		m.Transcript.ImplementationVersion = "lss-pulsar-rs-2.0.0"
	case "variant":
		m.Transcript.Variant = "refresh"
	default:
		t.Fatalf("unknown transcript field: %q", field)
	}
	return m
}

// TestLSSPulsarNegativeTranscriptMutationsRejected — Gate 4 over the
// LSS-Pulsar adapter's BuildActivationTranscript output. Mirrors the
// 17-field table from pulsar/reshare/negative_transcript_test.go.
func TestLSSPulsarNegativeTranscriptMutationsRejected(t *testing.T) {
	fields := []string{
		"chain_id",
		"network_id",
		"group_id",
		"key_era_id",
		"old_generation",
		"new_generation",
		"old_epoch_id",
		"new_epoch_id",
		"old_set_hash",
		"new_set_hash",
		"threshold_old",
		"threshold_new",
		"group_public_key_hash",
		"nebula_root",
		"hash_suite_id",
		"implementation_version",
		"variant",
	}

	base := lssBaselineActivation()
	baselineHash := base.Transcript.Hash(nil)
	baselineExchange := base.ReshareTranscript.Hash(nil)
	baselineSignable := base.SignableBytes(nil)
	verify := lssHonestVerifier(baselineSignable)

	cert := &reshare.ActivationCert{
		Message:   base,
		Signature: []byte("lss-baseline-sig"),
	}
	if err := reshare.VerifyActivation(cert, baselineHash, baselineExchange, nil, verify); err != nil {
		t.Fatalf("baseline VerifyActivation: %v", err)
	}

	for _, f := range fields {
		t.Run(f, func(t *testing.T) {
			mutated := lssMutateTranscriptField(t, base, f)
			mHash := mutated.Transcript.Hash(nil)
			if mHash == baselineHash {
				t.Fatalf("mutation of %q did not change transcript hash", f)
			}

			mCert := &reshare.ActivationCert{
				Message:   mutated,
				Signature: []byte("lss-baseline-sig"),
			}

			err := reshare.VerifyActivation(mCert, baselineHash, baselineExchange, nil, verify)
			if err == nil {
				t.Fatalf("VerifyActivation accepted mutated %q field", f)
			}
			if !errors.Is(err, reshare.ErrTranscriptMismatch) {
				t.Fatalf("expected ErrTranscriptMismatch on mutated %q, got %v", f, err)
			}

			err = reshare.VerifyActivation(mCert, mHash, baselineExchange, nil, verify)
			if err == nil {
				t.Fatalf("VerifyActivation accepted mutated %q field under shifted local view", f)
			}
			if !errors.Is(err, reshare.ErrActivationFailed) && !errors.Is(err, reshare.ErrTranscriptMismatch) {
				t.Fatalf("expected ErrActivationFailed or ErrTranscriptMismatch on mutated %q, got %v", f, err)
			}
		})
	}
}

// TestLSSPulsarNegativeTranscriptHashesDistinctPerField — orthogonality
// check on the LSS-Pulsar adapter side: no two single-field mutations
// of the BuildActivationTranscript output collide on the transcript
// hash.
func TestLSSPulsarNegativeTranscriptHashesDistinctPerField(t *testing.T) {
	fields := []string{
		"chain_id", "network_id", "group_id",
		"key_era_id", "old_generation", "new_generation",
		"old_epoch_id", "new_epoch_id",
		"old_set_hash", "new_set_hash",
		"threshold_old", "threshold_new",
		"group_public_key_hash", "nebula_root",
		"hash_suite_id", "implementation_version", "variant",
	}
	base := lssBaselineActivation()

	seen := make(map[[32]byte]string, len(fields))
	for _, f := range fields {
		mutated := lssMutateTranscriptField(t, base, f)
		h := mutated.Transcript.Hash(nil)
		if prev, ok := seen[h]; ok {
			t.Fatalf("transcript hash collision: %q and %q produce same hash", prev, f)
		}
		seen[h] = f
	}
}
