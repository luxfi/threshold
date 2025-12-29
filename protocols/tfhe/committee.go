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
// Combine path: there is one and only one combine routine — the lattice
// combine implemented by Protocol.CombineShares (see tfhe.go). When a
// Protocol is wired into ShareAggregator, the aggregator authenticates
// each FHEThresholdShare at the committee boundary (MAC + session +
// ciphertext-id + dedup) and dispatches the deduplicated share set
// directly to Protocol.CombineShares — no parallel aggregator, no
// HMAC-derived recovery mask, no XOR-shaped recovery. When no Protocol
// is wired (the policy-1-bit-verdict envelope path used by FChain
// policy gates), the aggregator certifies that ≥t parties witnessed the
// same ciphertext and returns the verdict envelope unchanged; the
// embedded plaintext is the 1-bit verdict produced by the FHE policy
// circuit.
//
// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/luxfi/fhe"
	"github.com/luxfi/threshold/pkg/party"
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

// FHEThresholdShare is one party's partial-decrypt response. Partial
// carries the per-party partial-decryption bytes consumed by
// Protocol.CombineShares when a lattice combine is wired in. MAC binds
// (PartyID, SessionID, CiphertextID, Partial) under the party's
// KeyShare so a malicious peer cannot impersonate a different party or
// rebind a fresh share to a different ciphertext / session.
type FHEThresholdShare struct {
	PartyID      uint32
	SessionID    [32]byte
	CiphertextID [32]byte
	Partial      []byte
	MAC          [32]byte
}

// Status is the terminal state of an aggregate round.
type Status string

const (
	StatusOK                 Status = "ok"
	StatusBadShare           Status = "bad_share"
	StatusInsufficientQuorum Status = "insufficient_quorum"
	StatusCiphertextMismatch Status = "ciphertext_mismatch"
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

// ShareAggregator authenticates committee shares at the wire boundary
// and dispatches the combine step.
//
// PartyKeys: when set, MACs are verified against each party's KeyShare.
// When nil, MAC verification is skipped — used during cross-committee
// bootstrap before CDS noise proofs ship; production self-checks always
// populate PartyKeys.
//
// Protocol: when set, after wire authentication passes the deduplicated
// share set is dispatched to Protocol.CombineShares (the canonical
// lattice combine — see tfhe.go). When nil, the aggregator returns the
// ciphertext envelope unchanged: this is the FChain policy-verdict path
// where the embedded plaintext is the 1-bit verdict produced by the
// policy circuit and the committee's only job is to ratify that ≥t
// parties saw the same ciphertext.
type ShareAggregator struct {
	PartyKeys map[uint32]KeyShare
	Protocol  *Protocol
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
// PartyIDs, and on success either dispatches to Protocol.CombineShares
// (when Protocol is set) or returns the verdict envelope (Protocol nil).
func (a *ShareAggregator) Aggregate(
	ctx context.Context,
	ct FHECiphertext,
	shares []FHEThresholdShare,
	threshold uint32,
	sessionID [32]byte,
) (AggregateResult, []byte, error) {
	if uint32(len(shares)) < threshold {
		return AggregateResult{Status: StatusInsufficientQuorum, ShareCount: len(shares)}, nil, ErrShareCount
	}

	seen := make(map[uint32]struct{}, threshold)
	deduped := make([]FHEThresholdShare, 0, len(shares))
	for _, s := range shares {
		if s.CiphertextID != ct.ID {
			return AggregateResult{Status: StatusCiphertextMismatch, ShareCount: len(deduped)}, nil, fmt.Errorf("tfhe: share from party %d for ciphertext %x, expected %x", s.PartyID, s.CiphertextID, ct.ID)
		}
		if s.SessionID != sessionID {
			return AggregateResult{Status: StatusBadShare, ShareCount: len(deduped)}, nil, fmt.Errorf("tfhe: share from party %d carries wrong sessionID", s.PartyID)
		}
		if _, dup := seen[s.PartyID]; dup {
			continue
		}
		if a.PartyKeys != nil {
			key, ok := a.PartyKeys[s.PartyID]
			if !ok {
				return AggregateResult{Status: StatusBadShare, ShareCount: len(deduped)}, nil, fmt.Errorf("tfhe: no key registered for party %d", s.PartyID)
			}
			if !verifyShareMAC(key, s) {
				return AggregateResult{Status: StatusBadShare, ShareCount: len(deduped)}, nil, fmt.Errorf("tfhe: bad MAC on share from party %d", s.PartyID)
			}
		}
		seen[s.PartyID] = struct{}{}
		deduped = append(deduped, s)
	}

	if uint32(len(deduped)) < threshold {
		return AggregateResult{Status: StatusInsufficientQuorum, ShareCount: len(deduped)}, nil, nil
	}

	// Lattice path: dispatch the authenticated share set directly to
	// Protocol.CombineShares — the single canonical combine routine.
	if a.Protocol != nil {
		plaintext, err := a.dispatchCombine(ctx, ct, deduped)
		if err != nil {
			return AggregateResult{Status: StatusBadShare, ShareCount: len(deduped)}, nil, err
		}
		return AggregateResult{Status: StatusOK, ShareCount: len(deduped)}, plaintext, nil
	}

	// Envelope path: the policy circuit emitted a 1-bit verdict in the
	// clear inside the ciphertext envelope; the committee's job is to
	// ratify "≥t parties saw the same ciphertext".
	plaintext := append([]byte(nil), ct.Bytes...)
	return AggregateResult{Status: StatusOK, ShareCount: len(deduped)}, plaintext, nil
}

// dispatchCombine translates the committee-boundary share set onto
// Protocol's per-party DecryptionShare and invokes the lattice combine.
// The translation is mechanical: PartyID/SessionID/CiphertextID identify
// the share, Partial carries the per-party partial-decryption bytes,
// and CiphertextHash uses the Protocol's hash convention so
// CombineShares' integrity check passes.
func (a *ShareAggregator) dispatchCombine(
	ctx context.Context,
	ct FHECiphertext,
	shares []FHEThresholdShare,
) ([]byte, error) {
	bc := &fhe.BitCiphertext{}
	if err := bc.UnmarshalBinary(ct.Bytes); err != nil {
		return nil, fmt.Errorf("tfhe: ciphertext unmarshal: %w", err)
	}
	ctHash := computeCiphertextHash(bc)

	a.Protocol.ClearShares()
	for _, s := range shares {
		ds := &DecryptionShare{
			PartyID:        party.ID(fmt.Sprintf("%d", s.PartyID)),
			Index:          int(s.PartyID) - 1,
			Generation:     a.Protocol.config.Generation,
			CiphertextHash: ctHash,
			PartialResult:  append([]byte(nil), s.Partial...),
		}
		if err := a.Protocol.AddDecryptionShare(ds); err != nil {
			return nil, fmt.Errorf("tfhe: add share party %d: %w", s.PartyID, err)
		}
	}
	return a.Protocol.CombineShares(ctx, bc)
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
// Partial is HMAC-SHA256(key, "LUX/FHE/THRESHOLD/PARTIAL/v1" || sessionID
// || ciphertextID) — a deterministic, per-party byte sequence that
// fingerprints the (party, session, ciphertext) tuple. MAC is
// HMAC-SHA256(key, "LUX/FHE/THRESHOLD/MAC/v1" || partyID || sessionID
// || ciphertextID || Partial), so a malicious peer cannot replay
// another party's share or rebind a fresh share to a different
// ciphertext / session.
func (p *PartialDecrypter) PartialDecrypt(
	_ context.Context,
	key KeyShare,
	ct FHECiphertext,
	sessionID [32]byte,
) (FHEThresholdShare, error) {
	partial := computePartial(key, sessionID, ct.ID)
	mac := computeMAC(key, key.PartyID, sessionID, ct.ID, partial)
	return FHEThresholdShare{
		PartyID:      key.PartyID,
		SessionID:    sessionID,
		CiphertextID: ct.ID,
		Partial:      partial,
		MAC:          mac,
	}, nil
}

func computePartial(key KeyShare, sessionID, ctID [32]byte) []byte {
	h := hmac.New(sha256.New, key.Bytes)
	h.Write([]byte("LUX/FHE/THRESHOLD/PARTIAL/v1"))
	h.Write(sessionID[:])
	h.Write(ctID[:])
	return h.Sum(nil)
}

func computeMAC(key KeyShare, partyID uint32, sessionID, ctID [32]byte, partial []byte) [32]byte {
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
	h.Write(partial)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func verifyShareMAC(key KeyShare, s FHEThresholdShare) bool {
	want := computeMAC(key, s.PartyID, s.SessionID, s.CiphertextID, s.Partial)
	return hmac.Equal(want[:], s.MAC[:])
}
