// Package adapters provides protocol adapters for unified threshold signature interface.
package adapters

import (
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
)

// CMPConfigAdapter wraps a CMP config to implement ThresholdConfig
type CMPConfigAdapter struct {
	*cmpconfig.Config
}

// Ensure CMPConfigAdapter implements ThresholdConfig
var _ protocol.ThresholdConfig = (*CMPConfigAdapter)(nil)

// NewCMPAdapter creates a new CMP config adapter
func NewCMPAdapter(config *cmpconfig.Config) *CMPConfigAdapter {
	return &CMPConfigAdapter{Config: config}
}

// GetID returns the party ID
func (c *CMPConfigAdapter) GetID() party.ID {
	return c.ID
}

// GetThreshold returns the threshold value
func (c *CMPConfigAdapter) GetThreshold() int {
	return c.Threshold
}

// GetGroup returns the elliptic curve group
func (c *CMPConfigAdapter) GetGroup() curve.Curve {
	return c.Group
}

// GetPrivateShare returns the private key share
func (c *CMPConfigAdapter) GetPrivateShare() curve.Scalar {
	return c.ECDSA
}

// GetPublicKey returns the combined public key
func (c *CMPConfigAdapter) GetPublicKey() (curve.Point, error) {
	if c.PublicPoint() == nil {
		return nil, fmt.Errorf("public key not available")
	}
	return c.PublicPoint(), nil
}

// GetPublicShare returns a party's public share
func (c *CMPConfigAdapter) GetPublicShare(id party.ID) (curve.Point, error) {
	if pub, ok := c.Public[id]; ok && pub != nil {
		return pub.ECDSA, nil
	}
	return nil, fmt.Errorf("public share for party %s not found", id)
}

// GetChainKey returns the chain key
func (c *CMPConfigAdapter) GetChainKey() []byte {
	return c.ChainKey
}

// GetRID returns the RID
func (c *CMPConfigAdapter) GetRID() []byte {
	return c.RID
}

// Validate validates the configuration
func (c *CMPConfigAdapter) Validate() error {
	// CMP config validation
	if c.Config == nil {
		return fmt.Errorf("nil config")
	}
	if c.Threshold < 1 {
		return fmt.Errorf("invalid threshold: %d", c.Threshold)
	}
	return nil
}

// IsCompatible checks if two configs can work together
func (c *CMPConfigAdapter) IsCompatible(other protocol.ThresholdConfig) bool {
	if other == nil {
		return false
	}
	
	// Check if public keys match
	myPubKey, err1 := c.GetPublicKey()
	otherPubKey, err2 := other.GetPublicKey()
	if err1 != nil || err2 != nil {
		return false
	}
	
	if !myPubKey.Equal(otherPubKey) {
		return false
	}
	
	// Check if groups match
	if c.GetGroup().Name() != other.GetGroup().Name() {
		return false
	}
	
	return true
}

// CMPProtocolAdapter implements ThresholdProtocol for CMP
type CMPProtocolAdapter struct {
	pool *pool.Pool
}

// NewCMPProtocol creates a new CMP protocol adapter
func NewCMPProtocol(pl *pool.Pool) *CMPProtocolAdapter {
	return &CMPProtocolAdapter{pool: pl}
}

// Keygen initiates CMP key generation
func (p *CMPProtocolAdapter) Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int) (protocol.StartFunc, error) {
	return cmp.Keygen(group, selfID, participants, threshold, p.pool), nil
}

// Sign initiates CMP signing
func (p *CMPProtocolAdapter) Sign(config protocol.ThresholdConfig, signers []party.ID, message []byte) (protocol.StartFunc, error) {
	// Extract the underlying CMP config
	cmpAdapter, ok := config.(*CMPConfigAdapter)
	if !ok {
		return nil, fmt.Errorf("config is not a CMP config")
	}
	
	return cmp.Sign(cmpAdapter.Config, signers, message, p.pool), nil
}

// Refresh initiates CMP refresh
func (p *CMPProtocolAdapter) Refresh(config protocol.ThresholdConfig) (protocol.StartFunc, error) {
	cmpAdapter, ok := config.(*CMPConfigAdapter)
	if !ok {
		return nil, fmt.Errorf("config is not a CMP config")
	}
	
	return cmp.Refresh(cmpAdapter.Config, p.pool), nil
}

// GetScheme returns ECDSA for CMP
func (p *CMPProtocolAdapter) GetScheme() protocol.SignatureScheme {
	return protocol.ECDSA
}

// SupportsResharing returns false for CMP (native resharing not supported)
func (p *CMPProtocolAdapter) SupportsResharing() bool {
	return false
}