// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// One member's bound contribution, and the quorum-checked recovery.

package tfhe

import (
	"errors"
	"fmt"
	"sort"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// ErrQuorum reports fewer usable contributions than the threshold.
var ErrQuorum = errors.New("tfhe: insufficient decryption quorum")

// Decryption is one member's contribution to decrypting one ciphertext: one
// LWE partial decryption per bit, least significant first, bound by Digest to
// the ciphertext it was computed over. Decrypt rejects a mismatching Digest.
type Decryption struct {
	// From is the contributing member's 1-based committee position.
	From int `json:"from"`

	// Digest is Digest(ciphertext) for the ciphertext this contribution
	// decrypts.
	Digest [32]byte `json:"digest"`

	// Partials holds one partial decryption per ciphertext bit, LSB first.
	Partials []*Partial `json:"partials"`
}

// PartialDecrypt computes one member's contribution: the masked aggregate
// c_1·s_j + e_j for every bit, never the secret.
//
// prng supplies the smudging noise and is advanced per bit; a nil prng draws a
// fresh one per bit. A keyed prng makes a run reproducible.
func (m *Member) Decrypt(ciphertext []byte, prng sampling.PRNG) (Decryption, error) {
	if m == nil {
		return Decryption{}, fmt.Errorf("tfhe: nil member")
	}
	if err := m.Validate(); err != nil {
		return Decryption{}, err
	}
	params, err := m.Parameters()
	if err != nil {
		return Decryption{}, err
	}
	ct, err := Parse(ciphertext)
	if err != nil {
		return Decryption{}, err
	}

	bits := ct.Bits()
	partials := make([]*Partial, len(bits))
	for i, bit := range bits {
		p, err := m.Share.Partial(bit, params, m.Threshold, prng)
		if err != nil {
			return Decryption{}, fmt.Errorf("tfhe: partial decrypt bit %d: %w", i, err)
		}
		partials[i] = p
	}
	return Decryption{
		From:     m.Share.Index,
		Digest:   Digest(ciphertext),
		Partials: partials,
	}, nil
}

// Decrypt recovers the plaintext bits of ciphertext, least significant first,
// from contributions by distinct members. It uses exactly threshold of them,
// chosen to recombine exactly (Quorate), and refuses when the
// contributions on hand admit no such quorum. The key is never reconstructed.
func Decrypt(ciphertext []byte, from []Decryption, params fhe.Parameters, threshold int) ([]bool, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("tfhe: threshold must be at least 1, got %d", threshold)
	}
	ct, err := Parse(ciphertext)
	if err != nil {
		return nil, err
	}
	bits := ct.Bits()
	want := Digest(ciphertext)

	usable := make([]Decryption, 0, len(from))
	seen := make(map[int]struct{}, len(from))
	for _, d := range from {
		if d.Digest != want {
			return nil, fmt.Errorf("tfhe: member %d contributed a partial decryption of a different ciphertext", d.From)
		}
		if d.From < 1 {
			return nil, fmt.Errorf("tfhe: member position %d is not 1-based", d.From)
		}
		if len(d.Partials) != len(bits) {
			return nil, fmt.Errorf("tfhe: member %d contributed %d partials for %d bits", d.From, len(d.Partials), len(bits))
		}
		for i, p := range d.Partials {
			if p == nil {
				return nil, fmt.Errorf("tfhe: member %d partial for bit %d is nil", d.From, i)
			}
			if p.Index != d.From {
				return nil, fmt.Errorf("tfhe: member %d contributed a partial indexed %d", d.From, p.Index)
			}
		}
		if _, dup := seen[d.From]; dup {
			return nil, fmt.Errorf("tfhe: member %d contributed twice", d.From)
		}
		seen[d.From] = struct{}{}
		usable = append(usable, d)
	}
	if len(usable) < threshold {
		return nil, fmt.Errorf("%w: have %d of %d", ErrQuorum, len(usable), threshold)
	}

	sort.Slice(usable, func(i, j int) bool { return usable[i].From < usable[j].From })
	quorum, ok := pick(usable, threshold)
	if !ok {
		positions := make([]int, len(usable))
		for i, d := range usable {
			positions[i] = d.From
		}
		return nil, fmt.Errorf("tfhe: no quorum of %d among members %v recombines exactly; "+
			"one more member's contribution would supply one", threshold, positions)
	}

	out := make([]bool, len(bits))
	partials := make([]*Partial, threshold)
	for i, bit := range bits {
		for j, d := range quorum {
			partials[j] = d.Partials[i]
		}
		b, err := Combine(bit, partials, params)
		if err != nil {
			return nil, fmt.Errorf("tfhe: combine bit %d: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}

// Quorum reports whether the given member positions contain a subset of
// size threshold that recombines exactly. Reaching the threshold count is not
// sufficient on its own.
func Quorum(positions []int, threshold int) bool {
	ascending := append([]int(nil), positions...)
	sort.Ints(ascending)
	_, ok := choose(ascending, threshold)
	return ok
}

// pick chooses threshold contributions that recombine exactly,
// preferring the largest positions. from must be sorted by position ascending.
func pick(from []Decryption, threshold int) ([]Decryption, bool) {
	positions := make([]int, len(from))
	for i, d := range from {
		positions[i] = d.From
	}
	slots, ok := choose(positions, threshold)
	if !ok {
		return nil, false
	}
	out := make([]Decryption, len(slots))
	for i, slot := range slots {
		out[i] = from[slot]
	}
	return out, true
}

// choose returns the offsets, into an ascending position list, of a
// subset of size threshold that recombines exactly. Largest positions are
// tried first. positions must be sorted ascending; the search is bounded to
// the maxSearch largest.
func choose(positions []int, threshold int) ([]int, bool) {
	n := len(positions)
	if threshold < 1 || n < threshold {
		return nil, false
	}
	offset := 0
	if n > maxSearch {
		offset = n - maxSearch
		positions = positions[offset:]
		n = maxSearch
	}

	pick := make([]int, threshold)
	candidate := make([]int, threshold)
	var found []int
	var search func(slot, upper int) bool
	search = func(slot, upper int) bool {
		if slot < 0 {
			for i, idx := range pick {
				candidate[i] = positions[idx]
			}
			if !Quorate(candidate) {
				return false
			}
			found = make([]int, threshold)
			for i, idx := range pick {
				found[i] = idx + offset
			}
			return true
		}
		for i := upper; i >= slot; i-- {
			pick[slot] = i
			if search(slot-1, i-1) {
				return true
			}
		}
		return false
	}
	if search(threshold-1, n-1) {
		return found, true
	}
	return nil, false
}

// maxSearch caps the quorum search.
const maxSearch = 16
