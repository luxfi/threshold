// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"testing"
)

// server_test.go — ZAP-side correctness + benchmark tests. The prior
// HTTP↔ZAP parity tests are gone with the HTTP path; cryptographic
// correctness across the ZAP wire is asserted by thresholdd_test.go
// (full per-scheme round-trips) and the dedicated tests here.

// TestZapShares_RoundTrip covers the EncodeShares / DecodeShares
// helper. Trivial layout, but a regression here would corrupt every
// keygen response, so pin it.
func TestZapShares_RoundTrip(t *testing.T) {
	cases := [][]string{
		nil,
		{},
		{"1"},
		{"1", "2", "3"},
		{"", "a", "bb", "ccc", "1234567890"},
		{"long-string-share-id-that-should-still-survive-the-round-trip"},
	}
	for i, in := range cases {
		buf := EncodeShares(in)
		out, err := DecodeShares(buf)
		if err != nil {
			t.Errorf("case %d: DecodeShares: %v", i, err)
			continue
		}
		if len(out) != len(in) {
			t.Errorf("case %d: len=%d want=%d", i, len(out), len(in))
			continue
		}
		for j := range in {
			if in[j] != out[j] {
				t.Errorf("case %d/%d: %q != %q", i, j, in[j], out[j])
			}
		}
	}
}

// TestZapShares_TruncatedBlob asserts the decoder refuses partial
// input rather than silently returning a partial list.
func TestZapShares_TruncatedBlob(t *testing.T) {
	buf := EncodeShares([]string{"a", "bc", "def"})
	for cut := 1; cut < len(buf); cut++ {
		_, err := DecodeShares(buf[:cut])
		if err == nil {
			t.Errorf("cut=%d: expected error on truncated input", cut)
		}
	}
}

// TestProcOpcode_StableAndNonReserved spot-checks the FNV-1a opcode
// derivation. The procedure set is small + fixed; collisions here
// would route the wrong handler.
func TestProcOpcode_StableAndNonReserved(t *testing.T) {
	seen := make(map[uint16]string)
	for _, p := range allProcedures {
		op := procOpcode(p.name)
		// upper byte must be 1..254 (zapclient reserves 0 and 0xff)
		hi := byte(op >> 8)
		if hi == 0x00 || hi == 0xff {
			t.Errorf("proc %q hashes to reserved opcode 0x%04x", p.name, op)
		}
		if existing, dup := seen[op]; dup {
			t.Errorf("opcode collision: %q and %q both hash to 0x%04x — rename one", existing, p.name, op)
		}
		seen[op] = p.name
	}
}
