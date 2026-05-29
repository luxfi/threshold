// Package tfhe — committee surface for the threshold-FHE policy gate.
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
// SECURITY: this layer is the wire-authentication layer. It authenticates
// each FHEThresholdShare's MAC against the party's KeyShare, enforces
// session binding (sessionID + ciphertextID), dedupes party IDs, then
// dispatches the validated set to Protocol.CombineShares (the canonical
// lattice combine — see tfhe.go). The committee KeyShare is symmetric
// and only authenticates the wire — it is not part of the lattice
// secret-sharing scheme; that lives in Protocol.SecretKeyShare.
//
// Two dispatch paths:
//
//   - Lattice path: when Protocol is set, the authenticated share set
//     dispatches directly to Protocol.CombineShares. The partial bytes
//     are interpreted as a serialized fhethreshold.LWEPartialDecryption
//     and Lagrange-combined to yield the plaintext.
//
//   - Envelope path (default when Protocol is nil): the policy circuit
//     emitted a 1-bit verdict in the clear inside the ciphertext envelope,
//     and the committee's only job is to ratify "≥t parties saw the same
//     ciphertext". This is the FChain policy gate path.
//
// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"

	"github.com/luxfi/fhe"
	fhethreshold "github.com/luxfi/fhe/pkg/threshold"
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
//
// SECURITY: KeyShare authenticates the WIRE — it is not a share of the
// FHE secret. That lives in Protocol.SecretKeyShare.LWE.
type KeyShare struct {
	PartyID uint32
	Bytes   []byte
}

// FHEThresholdShare is one party's partial-decrypt response.
//
// Partial carries the per-party partial-decryption bytes consumed by the
// lattice combine. The encoded form is a gob-serialized
// fhethreshold.LWEPartialDecryption when dispatching to a Protocol; or
// an HMAC tag of (party, session, ciphertext) when the policy-1-bit-
// verdict envelope path is in use (Protocol nil).
//
// MAC binds (PartyID, SessionID, CiphertextID, Partial) under the
// party's KeyShare so a malicious peer cannot impersonate a different
// party or rebind a fresh share to a different ciphertext / session.
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
// Protocol: when set, the authenticated share set is decoded into per-
// bit LWEPartialDecryption values and dispatched to Protocol.CombineShares
// (the canonical lattice combine — see tfhe.go). When nil, the
// aggregator returns the ciphertext envelope unchanged: this is the
// FChain policy-verdict path where the embedded plaintext is the 1-bit
// verdict produced by the policy circuit and the committee's only job
// is to ratify that ≥t parties saw the same ciphertext.
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

// dispatchCombine decodes each share's Partial bytes into a per-bit
// LWEPartialDecryption set and invokes the lattice combine via
// Protocol.CombineShares. The ciphertext envelope bytes are unmarshaled
// into a BitCiphertext to obtain the per-bit list.
func (a *ShareAggregator) dispatchCombine(
	ctx context.Context,
	ct FHECiphertext,
	shares []FHEThresholdShare,
) ([]byte, error) {
	// Unmarshal the BitCiphertext from the envelope.
	bc := &fhe.BitCiphertext{}
	if err := bc.UnmarshalBinary(ct.Bytes); err != nil {
		return nil, fmt.Errorf("tfhe: ciphertext unmarshal: %w", err)
	}
	ctHash, err := bitCiphertextHash(bc)
	if err != nil {
		return nil, fmt.Errorf("tfhe: hash ciphertext: %w", err)
	}

	a.Protocol.ClearShares()
	for _, s := range shares {
		partials, err := decodePartialDecryptions(s.Partial)
		if err != nil {
			return nil, fmt.Errorf("tfhe: decode partial from party %d: %w", s.PartyID, err)
		}
		ds := &DecryptionShare{
			PartyID:        party.ID(fmt.Sprintf("%d", s.PartyID)),
			Index:          int(s.PartyID),
			Generation:     a.Protocol.config.Generation,
			CiphertextHash: ctHash,
			PartialResult:  partials,
		}
		if err := a.Protocol.AddDecryptionShare(ds); err != nil {
			return nil, fmt.Errorf("tfhe: add share party %d: %w", s.PartyID, err)
		}
	}
	return a.Protocol.CombineShares(ctx, bc)
}

// PartialDecrypter is the per-party partial-decrypt engine. Given a
// (lattice) SecretKeyShare and an FHECiphertext, it produces a
// FHEThresholdShare bound to (sessionID, ciphertext.ID, party.id) via a
// MAC under the party's symmetric KeyShare.
//
// SECURITY: PartialDecrypter unwraps the envelope to call the lattice
// partial-decrypt (fhethreshold.PartialDecryptLWE), then wraps the
// result back up in the on-the-wire FHEThresholdShare. The lattice
// share itself never leaves the party.
type PartialDecrypter struct {
	// SecretShare is this party's Shamir share of the FHE secret key.
	// Required for the lattice partial-decrypt path.
	SecretShare *SecretKeyShare

	// Params are the FHE parameters used to encode the ciphertext.
	Params fhe.Parameters

	// Threshold is t in t-of-n. Needed to calibrate smudging noise.
	Threshold int
}

// NewPartialDecrypter returns a PartialDecrypter configured for a single
// party. SecretShare and Params must be non-nil; Threshold must be ≥ 1.
func NewPartialDecrypter(secretShare *SecretKeyShare, params fhe.Parameters, threshold int) *PartialDecrypter {
	return &PartialDecrypter{
		SecretShare: secretShare,
		Params:      params,
		Threshold:   threshold,
	}
}

// PartialDecrypt computes the party's share for the given ciphertext.
//
// The Partial field of the returned FHEThresholdShare carries the
// gob-serialized []*fhethreshold.LWEPartialDecryption (one entry per
// bit of the originating BitCiphertext). The MAC binds the entire
// envelope under the party's KeyShare so a malicious peer cannot
// impersonate or rebind.
func (p *PartialDecrypter) PartialDecrypt(
	ctx context.Context,
	key KeyShare,
	ct FHECiphertext,
	sessionID [32]byte,
) (FHEThresholdShare, error) {
	if p.SecretShare == nil {
		return FHEThresholdShare{}, fmt.Errorf("tfhe: PartialDecrypter not configured with SecretShare")
	}
	bc := &fhe.BitCiphertext{}
	if err := bc.UnmarshalBinary(ct.Bytes); err != nil {
		return FHEThresholdShare{}, fmt.Errorf("tfhe: ciphertext unmarshal: %w", err)
	}

	// Lattice partial decrypt per bit.
	bits := bc.Bits()
	partials := make([]*fhethreshold.LWEPartialDecryption, len(bits))
	for i, bit := range bits {
		partial, err := fhethreshold.PartialDecryptFHE(
			&p.SecretShare.LWE,
			bit,
			p.Params,
			p.Threshold,
			nil, // fresh PRNG per bit; convenience layer constructs one.
		)
		if err != nil {
			return FHEThresholdShare{}, fmt.Errorf("tfhe: partial decrypt bit %d: %w", i, err)
		}
		partials[i] = partial
	}

	partialBytes, err := encodePartialDecryptions(partials)
	if err != nil {
		return FHEThresholdShare{}, fmt.Errorf("tfhe: encode partials: %w", err)
	}

	mac := computeMAC(key, key.PartyID, sessionID, ct.ID, partialBytes)
	return FHEThresholdShare{
		PartyID:      key.PartyID,
		SessionID:    sessionID,
		CiphertextID: ct.ID,
		Partial:      partialBytes,
		MAC:          mac,
	}, nil
}

// EnvelopePartialDecrypter is the envelope-mode partial decrypter used
// by the FChain policy gate: the share's Partial field is an HMAC of
// (party, session, ciphertext) — no lattice math. The committee's job
// is to ratify "≥t parties saw the same ciphertext" rather than to
// decrypt anything. Detection: ShareAggregator with Protocol == nil
// routes to the envelope path.
//
// This is a discrete primitive from the lattice-domain PartialDecrypter:
// the two solve different problems and are not interchangeable.
type EnvelopePartialDecrypter struct{}

// NewEnvelopePartialDecrypter returns the envelope-mode partial
// decrypter. Stateless — safe to share across goroutines.
func NewEnvelopePartialDecrypter() *EnvelopePartialDecrypter {
	return &EnvelopePartialDecrypter{}
}

// PartialDecrypt produces an envelope-mode share bound to (sessionID,
// ciphertext.ID, party.id) under the party's KeyShare. The Partial bytes
// are an HMAC of (party, session, ciphertext) — they do NOT decrypt
// anything. The MAC binds the entire envelope so a malicious peer
// cannot impersonate or rebind.
func (e *EnvelopePartialDecrypter) PartialDecrypt(
	ctx context.Context,
	key KeyShare,
	ct FHECiphertext,
	sessionID [32]byte,
) (FHEThresholdShare, error) {
	partial := computeEnvelopePartial(key, sessionID, ct.ID)
	mac := computeMAC(key, key.PartyID, sessionID, ct.ID, partial)
	return FHEThresholdShare{
		PartyID:      key.PartyID,
		SessionID:    sessionID,
		CiphertextID: ct.ID,
		Partial:      partial,
		MAC:          mac,
	}, nil
}

// PartialDecryptEnvelopeOnly is a thin function form of
// EnvelopePartialDecrypter.PartialDecrypt for call sites that don't want
// to hold the (stateless) struct. Returns no error — the operation
// cannot fail (deterministic HMAC + MAC).
func PartialDecryptEnvelopeOnly(
	key KeyShare,
	ct FHECiphertext,
	sessionID [32]byte,
) FHEThresholdShare {
	s, _ := (&EnvelopePartialDecrypter{}).PartialDecrypt(context.Background(), key, ct, sessionID)
	return s
}

// computeEnvelopePartial computes the envelope-mode partial: HMAC of
// (party, session, ciphertext). Domain-separated from MAC.
func computeEnvelopePartial(key KeyShare, sessionID, ctID [32]byte) []byte {
	h := hmac.New(sha256.New, key.Bytes)
	h.Write([]byte("LUX/FHE/THRESHOLD/PARTIAL_ENVELOPE/v1"))
	h.Write(sessionID[:])
	h.Write(ctID[:])
	return h.Sum(nil)
}

func computeMAC(key KeyShare, partyID uint32, sessionID, ctID [32]byte, partial []byte) [32]byte {
	h := hmac.New(sha256.New, key.Bytes)
	h.Write([]byte("LUX/FHE/THRESHOLD/MAC/v1"))
	var pid [4]byte
	binary.BigEndian.PutUint32(pid[:], partyID)
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

// encodePartialDecryptions serializes a per-bit partial-decryption slice
// for transport in FHEThresholdShare.Partial. Gob is used because the
// type ships across version boundaries within the luxfi/threshold
// module and we control both ends; switching to CBOR is a future option
// once we standardize on a wire format for cross-module artifacts.
func encodePartialDecryptions(partials []*fhethreshold.LWEPartialDecryption) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(partials); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodePartialDecryptions deserializes a per-bit partial-decryption
// slice from FHEThresholdShare.Partial.
func decodePartialDecryptions(data []byte) ([]*fhethreshold.LWEPartialDecryption, error) {
	dec := gob.NewDecoder(bytes.NewReader(data))
	var out []*fhethreshold.LWEPartialDecryption
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// bitCiphertextHash computes a deterministic hash of a BitCiphertext for
// use as a CiphertextID. Hashes the MarshalBinary serialization.
func bitCiphertextHash(bc *fhe.BitCiphertext) ([32]byte, error) {
	data, err := bc.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}
