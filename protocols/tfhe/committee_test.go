// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Committee-layer tests. The reference polynomial and the smudging noise are
// seeded; a member's own contribution is not seedable, so key-dependent
// assertions run over fresh committees.

package tfhe

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// noiseSeed fixes the smudging noise of a partial decryption so a run is
// reproducible.
var noiseSeed = []byte("lux-threshold-tfhe-committee-test-noise-seed-v1")

// newCommittee runs a dealerless key generation and returns one Member per
// position.
func newCommittee(t *testing.T, threshold, total int) ([]*Member, fhe.Parameters) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	pub, shares, err := Keygen(params, threshold, total, crsSeed)
	if err != nil {
		t.Fatalf("dealerless key generation: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("encode collective public key: %v", err)
	}
	members := make([]*Member, total)
	for i := range shares {
		members[i] = &Member{
			Params:    fhe.PN10QP27,
			Threshold: threshold,
			Total:     total,
			Key:       pubBytes,
			Share:     shares[i],
		}
		if err := members[i].Validate(); err != nil {
			t.Fatalf("member %d: %v", i+1, err)
		}
	}
	return members, params
}

func keyedPRNG(t *testing.T, seed []byte) sampling.PRNG {
	t.Helper()
	prng, err := sampling.NewKeyedPRNG(seed)
	if err != nil {
		t.Fatalf("keyed prng: %v", err)
	}
	return prng
}

// contributions produces one seeded honest contribution per member.
func contributions(t *testing.T, members []*Member, ciphertext []byte) []Decryption {
	t.Helper()
	out := make([]Decryption, 0, len(members))
	for _, m := range members {
		seed := append(append([]byte(nil), noiseSeed...), byte(m.Share.Index))
		d, err := m.Decrypt(ciphertext, keyedPRNG(t, seed))
		if err != nil {
			t.Fatalf("partial decryption at position %d: %v", m.Share.Index, err)
		}
		out = append(out, d)
	}
	return out
}

// Known answers.

// TestDigest pins the ciphertext-binding digest.
func TestDigest(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "a15d43e63234fa25dc5bbf84f98d3d9af7c84580ff0970c722d9fae4fc1c1259"},
		{"committee-ciphertext", "993b70fea81381dce66503792e7faff1b62db2b8416128062dac87f47ea3fb95"},
	}
	for _, c := range cases {
		d := Digest([]byte(c.in))
		if got := hex.EncodeToString(d[:]); got != c.want {
			t.Errorf("Digest(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestTag checks the digest is not a bare SHA-256.
func TestTag(t *testing.T) {
	if Digest([]byte("x")) == Digest([]byte("y")) {
		t.Fatal("distinct ciphertexts share a digest")
	}
	if !strings.HasPrefix(digestTag, "LUX/THRESHOLD/TFHE/") {
		t.Fatalf("digest tag %q is not domain-separated", digestTag)
	}
}

// TestValue pins the bit-to-integer assembly, least significant
// bit first.
func TestValue(t *testing.T) {
	cases := []struct {
		bits []bool
		want uint64
	}{
		{nil, 0},
		{[]bool{false}, 0},
		{[]bool{true}, 1},
		{[]bool{false, true}, 2},
		{[]bool{true, false, true, false, false, true, false, true}, 0xA5},
		{[]bool{true, true, true, true, true, true, true, true}, 0xFF},
	}
	for _, c := range cases {
		if got := Value(c.bits); got != c.want {
			t.Errorf("Value(%v) = %#x, want %#x", c.bits, got, c.want)
		}
	}
}

// The persisted member record.

// TestMember checks each member gets one share at a distinct 1-based
// position, bound to the parameter set, plus the collective public key.
func TestMember(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	seen := map[int]bool{}
	for _, m := range members {
		if seen[m.Share.Index] {
			t.Fatalf("position %d issued twice", m.Share.Index)
		}
		seen[m.Share.Index] = true
		if m.Share.Q != params.QLWE() {
			t.Errorf("position %d bound to modulus %d, want %d", m.Share.Index, m.Share.Q, params.QLWE())
		}
		if m.Share.Total != 3 {
			t.Errorf("position %d records committee size %d, want 3", m.Share.Index, m.Share.Total)
		}
		if got, want := len(m.Share.Coeffs), params.ParamsLWE().RingQ().N(); got != want {
			t.Errorf("position %d share length %d, want %d", m.Share.Index, got, want)
		}
	}
	for i := 1; i <= 3; i++ {
		if !seen[i] {
			t.Errorf("no share at position %d", i)
		}
	}
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	if pub.PKLWE == nil {
		t.Fatal("collective public key carries no LWE key")
	}
}

// TestMarshal checks a stored member survives a key store.
func TestMarshal(t *testing.T) {
	members, _ := newCommittee(t, 2, 3)
	body, err := Marshal(members[1])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := Unmarshal(body)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Threshold != 2 || back.Total != 3 || back.Share.Index != 2 {
		t.Fatalf("round trip changed the committee: %+v", back)
	}
	if !bytes.Equal(back.Key, members[1].Key) {
		t.Fatal("round trip changed the collective public key")
	}
	if !equal(back.Share.Coeffs, members[1].Share.Coeffs) {
		t.Fatal("round trip changed the share")
	}
}

// TestValidate checks a share disagreeing with its
// parameter set is refused on load. Each case names the clause it exercises.
func TestValidate(t *testing.T) {
	members, _ := newCommittee(t, 2, 3)
	good := members[0]

	cases := []struct {
		name    string
		corrupt func(m *Member)
		want    string
	}{
		{"threshold above committee size", func(m *Member) { m.Threshold = 4 }, "threshold 4 out of range"},
		{"threshold below one", func(m *Member) { m.Threshold = 0 }, "threshold 0 out of range"},
		{"position outside committee", func(m *Member) { m.Share.Index = 9 }, "share index 9 out of range"},
		{"committee size disagrees", func(m *Member) { m.Share.Total = 5 }, "share committee size 5 disagrees"},
		{"modulus disagrees", func(m *Member) { m.Share.Q = 12345 }, "share modulus 12345 disagrees"},
		{"share truncated", func(m *Member) { m.Share.Coeffs = m.Share.Coeffs[:8] }, "share length 8 disagrees"},
		{"no collective public key", func(m *Member) { m.Key = nil }, "no collective public key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := *good
			m.Share.Coeffs = append([]uint64(nil), good.Share.Coeffs...)
			c.corrupt(&m)
			err := m.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a member with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Validate rejected for the wrong reason: %v, want %q", err, c.want)
			}
		})
	}
}

// Threshold decryption.

// TestDecrypt asserts the recovered integers at
// exactly the threshold number of contributions.
func TestDecrypt(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}

	for _, want := range []uint64{0x00, 0x01, 0xA5, 0xFF} {
		ciphertext, err := Encrypt(params, pub, want, fhe.FheUint8)
		if err != nil {
			t.Fatalf("encrypt %#x: %v", want, err)
		}
		// The last two members, so the quorum is not the trivial {1,2}.
		bits, err := Decrypt(ciphertext, contributions(t, members[1:], ciphertext), params, 2)
		if err != nil {
			t.Fatalf("decrypt %#x: %v", want, err)
		}
		if len(bits) != 8 {
			t.Fatalf("recovered %d bits, want 8", len(bits))
		}
		if got := Value(bits); got != want {
			t.Fatalf("recovered %#x, want %#x", got, want)
		}
	}
}

// TestThreshold checks threshold-1 members are refused.
func TestThreshold(t *testing.T) {
	members, params := newCommittee(t, 3, 5)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	ciphertext, err := Encrypt(params, pub, 1, fhe.FheBool)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = Decrypt(ciphertext, contributions(t, members[:2], ciphertext), params, 3)
	if err == nil {
		t.Fatal("Decrypt accepted 2 contributions for a 3-of-5 committee")
	}
	if !strings.Contains(err.Error(), ErrQuorum.Error()) {
		t.Fatalf("Decrypt refused for the wrong reason: %v, want a quorum failure", err)
	}
}

// TestSubthreshold checks threshold-1
// contributions do not recover the plaintext even past the quorum check.
func TestSubthreshold(t *testing.T) {
	members, params := newCommittee(t, 3, 5)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}

	wrong := 0
	const trials = 24
	for i := 0; i < trials; i++ {
		want := uint64(i & 1)
		ciphertext, err := Encrypt(params, pub, want, fhe.FheBool)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		bits, err := Decrypt(ciphertext, contributions(t, members[:2], ciphertext), params, 2)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if Value(bits) != want {
			wrong++
		}
	}
	if wrong == 0 {
		t.Fatalf("2 of 5 recovered the plaintext in all %d trials", trials)
	}
}

// TestBinding checks a partial decryption computed
// for one ciphertext is not combinable into another.
func TestBinding(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	first, err := Encrypt(params, pub, 1, fhe.FheBool)
	if err != nil {
		t.Fatalf("encrypt first: %v", err)
	}
	second, err := Encrypt(params, pub, 0, fhe.FheBool)
	if err != nil {
		t.Fatalf("encrypt second: %v", err)
	}

	stale := contributions(t, members[:2], first)
	if _, err := Decrypt(second, stale, params, 2); err == nil {
		t.Fatal("Decrypt accepted contributions to a different ciphertext")
	} else if !strings.Contains(err.Error(), "different ciphertext") {
		t.Fatalf("Decrypt refused for the wrong reason: %v", err)
	}

	// One honest contribution beside one replayed from the other ciphertext is
	// also refused: the mismatch is per contribution, not per batch.
	mixed := []Decryption{contributions(t, members[1:2], second)[0], stale[0]}
	if _, err := Decrypt(second, mixed, params, 2); err == nil {
		t.Fatal("Decrypt accepted one replayed contribution alongside an honest one")
	}
}

// TestMalformed covers the per-member checks.
// Each case names the clause it exercises.
func TestMalformed(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	ciphertext, err := Encrypt(params, pub, 1, fhe.FheBool)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	honest := contributions(t, members, ciphertext)

	cases := []struct {
		name string
		from func() []Decryption
		want string
	}{
		{
			name: "same member twice",
			from: func() []Decryption { return []Decryption{honest[0], honest[0]} },
			want: "contributed twice",
		},
		{
			name: "member position not 1-based",
			from: func() []Decryption {
				bad := honest[0]
				bad.From = 0
				return []Decryption{bad, honest[1]}
			},
			want: "is not 1-based",
		},
		{
			name: "partial count disagrees with bit width",
			from: func() []Decryption {
				bad := honest[0]
				bad.Partials = nil
				return []Decryption{bad, honest[1]}
			},
			want: "partials for 1 bits",
		},
		{
			name: "nil partial",
			from: func() []Decryption {
				bad := honest[0]
				bad.Partials = []*Partial{nil}
				return []Decryption{bad, honest[1]}
			},
			want: "is nil",
		},
		{
			name: "partial indexed as another member",
			from: func() []Decryption {
				bad := honest[0]
				stolen := *bad.Partials[0]
				stolen.Index = 2
				bad.Partials = []*Partial{&stolen}
				return []Decryption{bad, honest[1]}
			},
			want: "contributed a partial indexed 2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decrypt(ciphertext, c.from(), params, 2)
			if err == nil {
				t.Fatalf("Decrypt accepted contributions with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Decrypt refused for the wrong reason: %v, want %q", err, c.want)
			}
		})
	}
}

// TestTampered records the residual: a tampered
// partial decryption is not detected, so decryption returns a plaintext that
// is not trustworthy. A failure here means an integrity check was added and
// lux/proofs/fhe/threshold-custody.tex needs tightening.
func TestTampered(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	ciphertext, err := Encrypt(params, pub, 1, fhe.FheBool)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	from := contributions(t, members[:2], ciphertext)

	tampered := *from[0].Partials[0]
	tampered.Value = append([]uint64(nil), tampered.Value...)
	tampered.Value[0] = (tampered.Value[0] + params.QLWE()/4) % params.QLWE()
	from[0].Partials = []*Partial{&tampered}

	if _, err := Decrypt(ciphertext, from, params, 2); err != nil {
		t.Fatalf("Decrypt grew an integrity check (%v); tighten the custody proof", err)
	}
}

// TestParse covers the wire-form bounds.
func TestParse(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, "is 0 bytes"},
		{"truncated header", []byte{1, 0}, "is 2 bytes"},
		{"zero bits", []byte{0, 0, 0, 0, 0}, "declares 0 bits"},
		{"absurd width", []byte("hello"), "declares 1819043176 bits"},
		{"width in range, no body", []byte{1, 0, 0, 0, 0}, "decode ciphertext"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.in)
			if err == nil {
				t.Fatalf("Parse accepted %q", c.in)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused for the wrong reason: %v, want %q", err, c.want)
			}
		})
	}
}

// Reproducibility.

// TestSeeded checks the smudging noise is driven
// by the injected PRNG: same seed gives identical contributions, a different
// seed gives different ones.
func TestSeeded(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	ciphertext, err := Encrypt(params, pub, 1, fhe.FheUint8)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	first, err := members[0].Decrypt(ciphertext, keyedPRNG(t, noiseSeed))
	if err != nil {
		t.Fatalf("first contribution: %v", err)
	}
	again, err := members[0].Decrypt(ciphertext, keyedPRNG(t, noiseSeed))
	if err != nil {
		t.Fatalf("second contribution: %v", err)
	}
	if fingerprint(t, first) != fingerprint(t, again) {
		t.Fatal("same seed produced different contributions")
	}

	other, err := members[0].Decrypt(ciphertext, keyedPRNG(t, []byte("a-different-noise-seed")))
	if err != nil {
		t.Fatalf("third contribution: %v", err)
	}
	if fingerprint(t, first) == fingerprint(t, other) {
		t.Fatal("different seeds produced identical contributions")
	}
}

// TestReproducible checks a fully seeded quorum
// recovers the encrypted value.
func TestReproducible(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	const want = uint64(0x5A)
	ciphertext, err := Encrypt(params, pub, want, fhe.FheUint8)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	bits, err := Decrypt(ciphertext, contributions(t, members[:2], ciphertext), params, 2)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got := Value(bits); got != want {
		t.Fatalf("recovered %#x, want %#x", got, want)
	}
}

// fingerprint is a stable summary of a contribution's bytes.
func fingerprint(t *testing.T, d Decryption) string {
	t.Helper()
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return fmt.Sprintf("%x", Digest(body))
}
