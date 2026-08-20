package reveal

// A ciphertext is written where the parties are not, and an answer is written
// by a party that is not the one combining. So both cross a wire, and both need
// an encoding that belongs to them rather than to whoever happens to carry them.
//
// Points and scalars are interfaces: their bytes mean nothing without the group
// they came from. So decoding TAKES the group, the way EmptyConfig does, and a
// record decoded under the wrong one fails there rather than becoming a valid
// value of the wrong curve.

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

type wireCiphertext struct {
	R    []byte `cbor:"r"`
	Body []byte `cbor:"body"`
}

type wireAnswer struct {
	ID party.ID `cbor:"id"`
	D  []byte   `cbor:"d"`
	E  []byte   `cbor:"e"`
	Z  []byte   `cbor:"z"`
}

// MarshalBinary encodes the ciphertext.
func (c *Ciphertext) MarshalBinary() ([]byte, error) {
	if c == nil || c.R == nil {
		return nil, fmt.Errorf("reveal: encoding a ciphertext with no ephemeral point")
	}
	r, err := c.R.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("reveal: encode R: %w", err)
	}
	return cbor.Marshal(wireCiphertext{R: r, Body: c.Body})
}

// UnmarshalCiphertext decodes a ciphertext over the group that produced it.
func UnmarshalCiphertext(group curve.Curve, b []byte) (*Ciphertext, error) {
	var w wireCiphertext
	if err := cbor.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("reveal: decode ciphertext: %w", err)
	}
	R := group.NewPoint()
	if err := R.UnmarshalBinary(w.R); err != nil {
		return nil, fmt.Errorf("reveal: decode R: %w", err)
	}
	return &Ciphertext{R: R, Body: w.Body}, nil
}

// MarshalBinary encodes one party's answer.
func (a *Answer) MarshalBinary() ([]byte, error) {
	if a == nil || a.D == nil || a.E == nil || a.Z == nil {
		return nil, fmt.Errorf("reveal: encoding an incomplete answer")
	}
	d, err := a.D.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("reveal: encode D: %w", err)
	}
	e, err := a.E.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("reveal: encode E: %w", err)
	}
	z, err := a.Z.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("reveal: encode Z: %w", err)
	}
	return cbor.Marshal(wireAnswer{ID: a.ID, D: d, E: e, Z: z})
}

// UnmarshalAnswer decodes an answer over the group that produced it.
//
// A decoded answer is not a trusted one: it proves nothing until Open checks it
// against the verification share for the party it names.
func UnmarshalAnswer(group curve.Curve, b []byte) (*Answer, error) {
	var w wireAnswer
	if err := cbor.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("reveal: decode answer: %w", err)
	}
	if w.ID == "" {
		return nil, fmt.Errorf("reveal: an answer names no party")
	}
	D := group.NewPoint()
	if err := D.UnmarshalBinary(w.D); err != nil {
		return nil, fmt.Errorf("reveal: decode D: %w", err)
	}
	E := group.NewScalar()
	if err := E.UnmarshalBinary(w.E); err != nil {
		return nil, fmt.Errorf("reveal: decode E: %w", err)
	}
	Z := group.NewScalar()
	if err := Z.UnmarshalBinary(w.Z); err != nil {
		return nil, fmt.Errorf("reveal: decode Z: %w", err)
	}
	return &Answer{ID: w.ID, D: D, E: E, Z: Z}, nil
}
