package curve

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"

	r255 "github.com/gtank/ristretto255"
)

// Hashing a message to a GROUP ELEMENT, which is a different operation from
// hashing it to a scalar and is not interchangeable with one.
//
// FromHash gives a scalar s, and s·G is a point — but the caller then knows
// that point's discrete logarithm. Anything whose security rests on the caller
// NOT knowing it is broken by that substitution. An oblivious PRF is the clear
// case: F(k, x) = k·H(x) is a PRF the key holder gates, and a client that knows
// h with H(x) = h·G computes k·H(x) = h·(k·G) from the public key alone, for
// every x, without asking. The map below has no such shortcut: nobody learns a
// discrete logarithm from it.

// ErrHashLength is returned for a length expand_message_xmd cannot produce.
var ErrHashLength = errors.New("curve: requested hash length out of range")

// expandXMD is expand_message_xmd with SHA-512 (RFC 9380 §5.3.1): a
// domain-separated extendable output built from a fixed-width hash.
//
// b_0 = H(Z_pad ‖ msg ‖ I2OSP(len,2) ‖ I2OSP(0,1) ‖ DST')
// b_1 = H(b_0 ‖ I2OSP(1,1) ‖ DST'), b_i = H(b_0 ⊕ b_{i-1} ‖ I2OSP(i,1) ‖ DST')
//
// DST' carries its own length, which is what keeps two different tags from
// producing the same stream.
func expandXMD(msg, dst []byte, length int) ([]byte, error) {
	const bInBytes = sha512.Size  // 64
	const sInBytes = 128          // SHA-512 block
	if length <= 0 || length > 255*bInBytes || len(dst) > 255 {
		return nil, ErrHashLength
	}
	ell := (length + bInBytes - 1) / bInBytes

	dstPrime := append(append([]byte{}, dst...), byte(len(dst)))

	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(length))

	h := sha512.New()
	h.Write(make([]byte, sInBytes)) // Z_pad
	h.Write(msg)
	h.Write(lenBytes[:])
	h.Write([]byte{0})
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	h.Reset()
	h.Write(b0)
	h.Write([]byte{1})
	h.Write(dstPrime)
	bi := h.Sum(nil)

	out := append([]byte{}, bi...)
	for i := 2; i <= ell; i++ {
		tmp := make([]byte, bInBytes)
		for j := range tmp {
			tmp[j] = b0[j] ^ bi[j]
		}
		h.Reset()
		h.Write(tmp)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bi = h.Sum(nil)
		out = append(out, bi...)
	}
	return out[:length], nil
}

// HashToPoint maps a message to a group element under a domain separation tag,
// as hash_to_ristretto255 (RFC 9380 §B): expand to 64 uniform bytes and apply
// the ristretto255 one-way map.
//
// Every tag gives an independent map, so two protocols sharing this group
// cannot be made to answer each other's questions.
func (Ristretto255) HashToPoint(dst, msg []byte) (Point, error) {
	uniform, err := expandXMD(msg, dst, 64)
	if err != nil {
		return nil, err
	}
	return &Ristretto255Point{value: r255.NewElement().FromUniformBytes(uniform)}, nil
}
