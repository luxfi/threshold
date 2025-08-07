package adapters

import (
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	frostconfig "github.com/luxfi/threshold/protocols/frost/keygen"
)

// FROSTConfigAdapter wraps a FROST config to implement ThresholdConfig
type FROSTConfigAdapter struct {
	*frostconfig.Config
}

// Ensure FROSTConfigAdapter implements ThresholdConfig
var _ protocol.ThresholdConfig = (*FROSTConfigAdapter)(nil)

// NewFROSTAdapter creates a new FROST config adapter
func NewFROSTAdapter(config *frostconfig.Config) *FROSTConfigAdapter {
	return &FROSTConfigAdapter{Config: config}
}

// GetID returns the party ID
func (f *FROSTConfigAdapter) GetID() party.ID {
	return f.ID
}

// GetThreshold returns the threshold value
func (f *FROSTConfigAdapter) GetThreshold() int {
	return f.Threshold
}

// GetGroup returns the elliptic curve group
func (f *FROSTConfigAdapter) GetGroup() curve.Curve {
	// FROST config doesn't store group directly, derive from PublicKey
	if f.PublicKey != nil {
		return f.PublicKey.Curve()
	}
	if f.PrivateShare != nil {
		return f.PrivateShare.Curve()
	}
	return nil
}

// GetPrivateShare returns the private key share
func (f *FROSTConfigAdapter) GetPrivateShare() curve.Scalar {
	return f.PrivateShare
}

// GetPublicKey returns the combined public key
func (f *FROSTConfigAdapter) GetPublicKey() (curve.Point, error) {
	if f.PublicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}
	return f.PublicKey, nil
}

// GetPublicShare returns a party's public share (verification share in FROST)
func (f *FROSTConfigAdapter) GetPublicShare(id party.ID) (curve.Point, error) {
	if f.VerificationShares == nil {
		return nil, fmt.Errorf("verification shares not available")
	}
	
	if share, ok := f.VerificationShares.Points[id]; ok {
		return share, nil
	}
	
	return nil, fmt.Errorf("verification share for party %s not found", id)
}

// GetChainKey returns the chain key
func (f *FROSTConfigAdapter) GetChainKey() []byte {
	return f.ChainKey
}

// GetRID returns empty for FROST (no RID concept)
func (f *FROSTConfigAdapter) GetRID() []byte {
	return nil
}

// Validate validates the configuration
func (f *FROSTConfigAdapter) Validate() error {
	if f.Config == nil {
		return fmt.Errorf("nil config")
	}
	if f.Threshold < 1 {
		return fmt.Errorf("invalid threshold: %d", f.Threshold)
	}
	if f.PrivateShare == nil {
		return fmt.Errorf("missing private share")
	}
	if f.PublicKey == nil {
		return fmt.Errorf("missing public key")
	}
	return nil
}

// IsCompatible checks if two configs can work together
func (f *FROSTConfigAdapter) IsCompatible(other protocol.ThresholdConfig) bool {
	if other == nil {
		return false
	}
	
	// Check if public keys match
	myPubKey, err1 := f.GetPublicKey()
	otherPubKey, err2 := other.GetPublicKey()
	if err1 != nil || err2 != nil {
		return false
	}
	
	if !myPubKey.Equal(otherPubKey) {
		return false
	}
	
	// Check if groups match
	myGroup := f.GetGroup()
	otherGroup := other.GetGroup()
	if myGroup == nil || otherGroup == nil {
		return false
	}
	
	if myGroup.Name() != otherGroup.Name() {
		return false
	}
	
	return true
}

// FROSTProtocolAdapter implements ThresholdProtocol for FROST
type FROSTProtocolAdapter struct{}

// NewFROSTProtocol creates a new FROST protocol adapter
func NewFROSTProtocol() *FROSTProtocolAdapter {
	return &FROSTProtocolAdapter{}
}

// Keygen initiates FROST key generation
func (p *FROSTProtocolAdapter) Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int) (protocol.StartFunc, error) {
	return frost.Keygen(group, selfID, participants, threshold), nil
}

// Sign initiates FROST signing
func (p *FROSTProtocolAdapter) Sign(config protocol.ThresholdConfig, signers []party.ID, message []byte) (protocol.StartFunc, error) {
	// Extract the underlying FROST config
	frostAdapter, ok := config.(*FROSTConfigAdapter)
	if !ok {
		return nil, fmt.Errorf("config is not a FROST config")
	}
	
	return frost.Sign(frostAdapter.Config, signers, message), nil
}

// Refresh initiates FROST refresh
func (p *FROSTProtocolAdapter) Refresh(config protocol.ThresholdConfig) (protocol.StartFunc, error) {
	frostAdapter, ok := config.(*FROSTConfigAdapter)
	if !ok {
		return nil, fmt.Errorf("config is not a FROST config")
	}
	
	// FROST doesn't have a direct refresh, but we can use keygen with existing key material
	// This would need to be implemented properly for production use
	participants := make([]party.ID, 0)
	for id := range frostAdapter.VerificationShares.Points {
		participants = append(participants, id)
	}
	
	// For now, just do a new keygen (not a true refresh)
	group := frostAdapter.GetGroup()
	if group == nil {
		return nil, fmt.Errorf("unable to determine group from config")
	}
	
	return frost.Keygen(group, frostAdapter.ID, participants, frostAdapter.Threshold), nil
}

// GetScheme returns Schnorr for FROST
func (p *FROSTProtocolAdapter) GetScheme() protocol.SignatureScheme {
	return protocol.Schnorr
}

// SupportsResharing returns false for FROST (native resharing not directly supported)
func (p *FROSTProtocolAdapter) SupportsResharing() bool {
	return false
}