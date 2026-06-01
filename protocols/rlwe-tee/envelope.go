// SPDX-License-Identifier: BSD-3-Clause

package rlwetee

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/luxfi/mpc/cc/attest"
	"github.com/luxfi/mpc/pkg/kms"
)

// Envelope is the minimal kms.CompositeAttestation implementation
// consumed by this package. Mirrors slhdsa-tee.Envelope so embedders
// that compose multiple primitives share the same plumbing.
type Envelope struct {
	Kind          attest.Kind
	EvidenceBytes []byte
	ExpectedNonce [32]byte
	RIM           [32]byte
	Hardware      [32]byte
	TEEPub        [32]byte
	VerifyOpts    []attest.Option
}

var _ kms.CompositeAttestation = (*Envelope)(nil)

// Verify implements kms.CompositeAttestation.Verify.
func (e *Envelope) Verify(expectedNonce [32]byte) (bool, error) {
	if subtle.ConstantTimeCompare(e.ExpectedNonce[:], expectedNonce[:]) != 1 {
		return false, nil
	}
	return true, nil
}

// VerifyEvidence implements kms.CompositeAttestation.VerifyEvidence.
func (e *Envelope) VerifyEvidence(ctx context.Context, opts ...attest.Option) ([]*attest.VerifiedReport, error) {
	if len(e.EvidenceBytes) == 0 {
		return nil, fmt.Errorf("%w: empty evidence", attest.ErrInvalidEvidence)
	}
	allOpts := append([]attest.Option{}, e.VerifyOpts...)
	allOpts = append(allOpts, opts...)
	rep, err := attest.Dispatch(ctx, e.Kind, e.EvidenceBytes, allOpts...)
	if err != nil {
		return nil, err
	}
	if err := defaultRIMCheck(rep, e.RIM); err != nil {
		return nil, err
	}
	return []*attest.VerifiedReport{rep}, nil
}

func (e *Envelope) RIMDigest() [32]byte           { return e.RIM }
func (e *Envelope) HardwareFingerprint() [32]byte { return e.Hardware }
func (e *Envelope) TEEPublicKey() [32]byte        { return e.TEEPub }

func (e *Envelope) EvidenceIssuers() []string {
	switch e.Kind {
	case attest.KindSEVSNP:
		return []string{kms.IssuerSEVSNP}
	case attest.KindTDX:
		return []string{kms.IssuerTDX}
	case attest.KindNRAS:
		return []string{kms.IssuerNVNRAS}
	default:
		return nil
	}
}

func defaultRIMCheck(rep *attest.VerifiedReport, expected [32]byte) error {
	if rep == nil {
		return errors.New("rlwe-tee: defaultRIMCheck: nil verified report")
	}
	got := sha256.Sum256(rep.Measurement)
	if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
		return fmt.Errorf("%w: report measurement does not fold to operator-asserted RIM", attest.ErrPolicy)
	}
	return nil
}
