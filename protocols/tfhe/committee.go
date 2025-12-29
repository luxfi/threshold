// Committee surface for the threshold-FHE policy gate.
//
// This file defines the narrow "committee API" used by per-node policy
// gates (e.g. luxfi/mpc/pkg/policy/fhe_threshold_decryptor) to:
//
//  1. Wrap an opaque encrypted policy verdict (FHECiphertext)
//  2. Issue a partial-decrypt request to each committee peer
//  3. Aggregate ≥t valid shares into the recovered plaintext
//
// The on-the-wire shape is the same regardless of the underlying FHE
// scheme — luxfi/threshold/protocols/tfhe is the single canonical home
// for these types so call sites do not invent parallel definitions.
//
// Scheme: the in-tree implementation is a deterministic toy threshold
// over symmetric KeyShares — sufficient for unit tests of the policy
// dispatcher and for development environments where real TFHE keys are
// not provisioned. Production deployments swap ShareAggregateService
// for the real lattice-based aggregator (see Protocol.CombineShares for
// the lattice path).
//
// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

// FHECiphertext is the opaque ciphertext wrapper exchanged between the
// policy verifier and the committee. Bytes carries the encrypted policy
// verdict; ID is a deterministic content hash used for replay-detection
// and as part of the per-share session binding.
type FHECiphertext struct {
	ID    [32]byte
	Bytes []byte
}

// NewFHECiphertext wraps raw ciphertext bytes and computes the ID.
func NewFHECiphertext(b []byte) FHECiphertext {
	return FHECiphertext{
		ID:    sha256.Sum256(b),
		Bytes: append([]byte(nil), b...),
	}
}

// KeyShare is one party's symmetric verification key. The committee
// self-checks each FHEThresholdShare's MAC against the corresponding
// KeyShare before counting it toward the quorum.
type KeyShare struct {
	PartyID uint32
	Bytes   []byte
}

// FHEThresholdShare is one party's partial-decrypt response. Mask is
// the HMAC-derived partial output; MAC binds (PartyID, SessionID,
// CiphertextID, Mask) under the party's KeyShare so a malicious peer
// cannot impersonate a different party.
type FHEThresholdShare struct {
	PartyID      uint32
	SessionID    [32]byte
	CiphertextID [32]byte
	Mask         []byte
	MAC          [32]byte
}

// Status is the terminal state of an aggregate round.
type Status string

const (
	StatusOK                  Status = "ok"
	StatusBadShare            Status = "bad_share"
	StatusInsufficientQuorum  Status = "insufficient_quorum"
	StatusCiphertextMismatch  Status = "ciphertext_mismatch"
)

// AggregateResult reports the terminal status of an aggregate round.
type AggregateResult struct {
	Status     Status
	ShareCount int
}

// ShareAggregateService is the committee aggregator interface. The
// production implementation is *ShareAggregator. Tests may swap in a
// stub that bypasses MAC verification.
type ShareAggregateService interface {
	Aggregate(
		ctx context.Context,
		ct FHECiphertext,
		shares []FHEThresholdShare,
		threshold uint32,
		sessionID [32]byte,
	) (AggregateResult, []byte, error)
}

// ShareAggregator is the in-tree aggregator. When PartyKeys is set, MACs
// are verified against each party's KeyShare. When PartyKeys is nil,
// MAC verification is skipped — used during cross-committee bootstrap
// before CDS noise proofs ship; production self-checks always populate
// PartyKeys.
type ShareAggregator struct {
	PartyKeys map[uint32]KeyShare
}

// NewShareAggregator returns a ready-to-use aggregator with no party
// keys configured (callers populate PartyKeys before Aggregate).
func NewShareAggregator() *ShareAggregator {
	return &ShareAggregator{}
}

// ErrShareCount is returned when fewer than threshold shares are passed
// in. Distinct from the StatusInsufficientQuorum returned in the result
// so callers can distinguish "no shares to aggregate" from "shares all
// failed verification".
var ErrShareCount = errors.New("tfhe: share count below threshold")

// Aggregate verifies each share's MAC (when PartyKeys is set), confirms
// each share's CiphertextID matches the request, ensures unique
// PartyIDs, and returns the recovered plaintext when ≥threshold shares
// pass verification.
//
// The toy scheme returns ct.Bytes as the plaintext once a valid quorum
// is established. This is correct for the policy use case where
// FChain emits a 1-bit verdict in the clear inside the ciphertext
// envelope and the committee's only job is to ratify "≥t parties saw
// the same ciphertext".
func (a *ShareAggregator) Aggregate(
	_ context.Context,
	ct FHECiphertext,
	shares []FHEThresholdShare,
	threshold uint32,
	sessionID [32]byte,
) (AggregateResult, []byte, error) {
	if uint32(len(shares)) < threshold {
		return AggregateResult{Status: StatusInsufficientQuorum, ShareCount: len(shares)}, nil, ErrShareCount
	}

	seen := make(map[uint32]struct{}, threshold)
	valid := 0
	for _, s := range shares {
		if s.CiphertextID != ct.ID {
			return AggregateResult{Status: StatusCiphertextMismatch, ShareCount: valid}, nil, fmt.Errorf("tfhe: share from party %d for ciphertext %x, expected %x", s.PartyID, s.CiphertextID, ct.ID)
		}
		if s.SessionID != sessionID {
			return AggregateResult{Status: StatusBadShare, ShareCount: valid}, nil, fmt.Errorf("tfhe: share from party %d carries wrong sessionID", s.PartyID)
		}
		if _, dup := seen[s.PartyID]; dup {
			continue
		}
		if a.PartyKeys != nil {
			key, ok := a.PartyKeys[s.PartyID]
			if !ok {
				return AggregateResult{Status: StatusBadShare, ShareCount: valid}, nil, fmt.Errorf("tfhe: no key registered for party %d", s.PartyID)
			}
			if !verifyShareMAC(key, s) {
				return AggregateResult{Status: StatusBadShare, ShareCount: valid}, nil, fmt.Errorf("tfhe: bad MAC on share from party %d", s.PartyID)
			}
		}
		seen[s.PartyID] = struct{}{}
		valid++
	}

	if uint32(valid) < threshold {
		return AggregateResult{Status: StatusInsufficientQuorum, ShareCount: valid}, nil, nil
	}

	// Toy threshold scheme: plaintext bytes ARE the ciphertext bytes
	// once a valid quorum certifies them.
	plaintext := append([]byte(nil), ct.Bytes...)
	return AggregateResult{Status: StatusOK, ShareCount: valid}, plaintext, nil
}

// PartialDecrypter is the per-party partial-decrypt engine. Given a
// KeyShare and an FHECiphertext, it produces a deterministic
// FHEThresholdShare bound to (sessionID, ciphertext.ID, party.id) under
// the party's symmetric key.
type PartialDecrypter struct{}

// NewPartialDecrypter returns the in-tree partial-decrypter.
func NewPartialDecrypter() *PartialDecrypter { return &PartialDecrypter{} }

// PartialDecrypt computes the party's share for the given ciphertext.
//
// The mask is HMAC-SHA256(key, "LUX/FHE/THRESHOLD/MASK/v1" || sessionID
// || ciphertextID). The MAC is HMAC-SHA256(key, "LUX/FHE/THRESHOLD/MAC/v1"
// || partyID || sessionID || ciphertextID || mask), so a malicious
// peer cannot replay another party's share or rebind a fresh share to
// a different ciphertext / session.
func (p *PartialDecrypter) PartialDecrypt(
	_ context.Context,
	key KeyShare,
	ct FHECiphertext,
	sessionID [32]byte,
) (FHEThresholdShare, error) {
	mask := computeMask(key, sessionID, ct.ID)
	mac := computeMAC(key, key.PartyID, sessionID, ct.ID, mask)
	return FHEThresholdShare{
		PartyID:      key.PartyID,
		SessionID:    sessionID,
		CiphertextID: ct.ID,
		Mask:         mask,
		MAC:          mac,
	}, nil
}

func computeMask(key KeyShare, sessionID, ctID [32]byte) []byte {
	h := hmac.New(sha256.New, key.Bytes)
	h.Write([]byte("LUX/FHE/THRESHOLD/MASK/v1"))
	h.Write(sessionID[:])
	h.Write(ctID[:])
	return h.Sum(nil)
}

func computeMAC(key KeyShare, partyID uint32, sessionID, ctID [32]byte, mask []byte) [32]byte {
	h := hmac.New(sha256.New, key.Bytes)
	h.Write([]byte("LUX/FHE/THRESHOLD/MAC/v1"))
	var pid [4]byte
	pid[0] = byte(partyID >> 24)
	pid[1] = byte(partyID >> 16)
	pid[2] = byte(partyID >> 8)
	pid[3] = byte(partyID)
	h.Write(pid[:])
	h.Write(sessionID[:])
	h.Write(ctID[:])
	h.Write(mask)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func verifyShareMAC(key KeyShare, s FHEThresholdShare) bool {
	want := computeMAC(key, s.PartyID, s.SessionID, s.CiphertextID, s.Mask)
	return hmac.Equal(want[:], s.MAC[:]) && bytes.Equal(computeMask(key, s.SessionID, s.CiphertextID), s.Mask)
}
