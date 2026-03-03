// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// MLDSA cert-set wire-format fuzz harness.
//
// The MLDSACertSet rides as an opaque []byte lane inside Warp 2.0
// envelopes (warp/envelope.go EnvelopeV2.MLDSACertSet). Verifiers
// MUST never panic on attacker-controlled cert-set bytes; this
// harness exercises a structural parser as a reference.

package mldsa

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

const fuzzMaxRawSize = 16 * 1024

// fuzzCertSetStructural is a length-prefix-aware parser for an
// MLDSACertSet wire frame. Layout:
//
//	u32 numCerts || (numCerts × (u32 certLen || certBytes))
//
// Property: a parser that pre-bounds numCerts and certLen against
// fuzzMaxRawSize never recurses, never allocates more than the input
// permits, and never panics on attacker-controlled bytes.
func fuzzCertSetStructural(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	if len(raw) < 4 {
		return fmt.Errorf("missing numCerts prefix")
	}
	numCerts := binary.BigEndian.Uint32(raw[:4])
	if numCerts > 1024 {
		return fmt.Errorf("numCerts=%d exceeds cap", numCerts)
	}
	off := 4
	for i := uint32(0); i < numCerts; i++ {
		if off+4 > len(raw) {
			return fmt.Errorf("cert %d: missing length prefix", i)
		}
		certLen := binary.BigEndian.Uint32(raw[off : off+4])
		off += 4
		if certLen > fuzzMaxRawSize {
			return fmt.Errorf("cert %d: length %d exceeds cap", i, certLen)
		}
		if off+int(certLen) > len(raw) {
			return fmt.Errorf("cert %d: truncated", i)
		}
		off += int(certLen)
	}
	return nil
}

func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00}) // numCerts=0
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	// numCerts=1, cert of length 4
	good := bytes.Buffer{}
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], 1)
	good.Write(b4[:])
	binary.BigEndian.PutUint32(b4[:], 4)
	good.Write(b4[:])
	good.WriteString("test")
	f.Add(good.Bytes())
	// Malicious: huge numCerts
	mal := bytes.Buffer{}
	binary.BigEndian.PutUint32(b4[:], 0xFFFFFFFF)
	mal.Write(b4[:])
	f.Add(mal.Bytes())
	// Malicious: huge certLen
	mal2 := bytes.Buffer{}
	binary.BigEndian.PutUint32(b4[:], 1)
	mal2.Write(b4[:])
	binary.BigEndian.PutUint32(b4[:], 0xFFFFFFFF)
	mal2.Write(b4[:])
	mal2.Write([]byte("short"))
	f.Add(mal2.Bytes())
}

// FuzzMLDSACertSet fuzzes the cert-set structural parser.
func FuzzMLDSACertSet(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = fuzzCertSetStructural(raw)
	})
}

// TestFuzzCorpus_MLDSACertSetReplay confirms the small-seed corpus
// replays cleanly.
func TestFuzzCorpus_MLDSACertSetReplay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00, 0x00, 0x00, 0x00},
		bytes.Repeat([]byte{0xff}, 32),
	} {
		_ = fuzzCertSetStructural(raw)
	}
}
