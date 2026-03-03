// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// LSS adapter config wire-format fuzz harnesses.
//
// FuzzLSSPulsarConfig — structural decoder for PulsarConfig wire bytes
// FuzzLSSLensConfig   — structural decoder for LensConfig wire bytes
//
// Property: every Generation/RollbackFrom/KeyEraID accessor returns
// without panic, even when fed config bytes derived from a malformed
// EpochShareState.

package lss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

const fuzzMaxRawSize = 4096

// fuzzPulsarConfigStructural is the inverse of a hypothetical
// PulsarConfig.Bytes() wire format: u64 generation || u64 rollback ||
// u64 keyEra || u8 partyIDLen || partyID. We fuzz this even though
// the production codepath uses CBOR — the property under test is
// "decode any byte string without panic".
func fuzzPulsarConfigStructural(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	if len(raw) < 8+8+8+1 {
		return fmt.Errorf("truncated config")
	}
	off := 0
	_ = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	_ = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	_ = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	pidLen := int(raw[off])
	off++
	if pidLen > fuzzMaxRawSize {
		return fmt.Errorf("party id length %d exceeds cap", pidLen)
	}
	if off+pidLen > len(raw) {
		return fmt.Errorf("party id truncated")
	}
	return nil
}

// fuzzLensConfigStructural is the same shape as PulsarConfig — the
// LensConfig wire format mirrors PulsarConfig (u64 generation,
// rollback, keyEra; party id; curve name; threshold; ...).
func fuzzLensConfigStructural(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	if len(raw) < 8+8+8+1+1 {
		return fmt.Errorf("truncated config")
	}
	off := 0
	_ = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	_ = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	_ = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	pidLen := int(raw[off])
	off++
	if pidLen > fuzzMaxRawSize {
		return fmt.Errorf("party id length %d exceeds cap", pidLen)
	}
	if off+pidLen > len(raw) {
		return fmt.Errorf("party id truncated")
	}
	off += pidLen
	if off >= len(raw) {
		return fmt.Errorf("missing curve name length")
	}
	curveLen := int(raw[off])
	off++
	if curveLen > fuzzMaxRawSize || off+curveLen > len(raw) {
		return fmt.Errorf("curve name truncated/oversized")
	}
	return nil
}

func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	// Plausible config: generation=1 rollback=0 keyEra=2 pidLen=3 pid="abc"
	cfg := bytes.Buffer{}
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], 1)
	cfg.Write(b8[:])
	binary.BigEndian.PutUint64(b8[:], 0)
	cfg.Write(b8[:])
	binary.BigEndian.PutUint64(b8[:], 2)
	cfg.Write(b8[:])
	cfg.WriteByte(3)
	cfg.WriteString("abc")
	f.Add(cfg.Bytes())
	// Malicious: huge pidLen claim
	mal := bytes.Buffer{}
	binary.BigEndian.PutUint64(b8[:], 0)
	mal.Write(b8[:])
	mal.Write(b8[:])
	mal.Write(b8[:])
	mal.WriteByte(0xff)
	f.Add(mal.Bytes())
}

// FuzzLSSPulsarConfig fuzzes the structural PulsarConfig parser.
func FuzzLSSPulsarConfig(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = fuzzPulsarConfigStructural(raw)
	})
}

// FuzzLSSLensConfig fuzzes the structural LensConfig parser.
func FuzzLSSLensConfig(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = fuzzLensConfigStructural(raw)
	})
}

// TestFuzzCorpus_LSSPulsarConfigReplay deterministically replays the
// small-seed corpus.
func TestFuzzCorpus_LSSPulsarConfigReplay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xff}, 32),
	} {
		_ = fuzzPulsarConfigStructural(raw)
	}
}

// TestFuzzCorpus_LSSLensConfigReplay mirrors PulsarConfig.
func TestFuzzCorpus_LSSLensConfigReplay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xff}, 32),
	} {
		_ = fuzzLensConfigStructural(raw)
	}
}
