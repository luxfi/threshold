// Package lss provides a unified suite for threshold signature protocols.
package lss

import (
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/adapters"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	frostconfig "github.com/luxfi/threshold/protocols/frost/keygen"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// Suite provides a clean abstraction over different threshold signature protocols.
// LSS (Layered Secret Sharing) acts as the unifying layer.
type Suite struct {
	backend protocol.ThresholdProtocol
	pool    *pool.Pool
}

// NewSuite creates a new LSS suite with the specified backend
func NewSuite(backend protocol.ThresholdProtocol, pl *pool.Pool) *Suite {
	return &Suite{backend: backend, pool: pl}
}

// WithCMP creates an LSS suite using CMP for ECDSA signatures
func WithCMP(pl *pool.Pool) *Suite {
	return NewSuite(adapters.NewCMPProtocol(pl), pl)
}

// WithFROST creates an LSS suite using FROST for Schnorr signatures  
func WithFROST(pl *pool.Pool) *Suite {
	return NewSuite(adapters.NewFROSTProtocol(), pl)
}

// Keygen generates a new distributed key
func (s *Suite) Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	startFunc, _ := s.backend.Keygen(group, selfID, participants, threshold)
	return startFunc
}

// Sign creates a signature
func (s *Suite) Sign(config protocol.ThresholdConfig, signers []party.ID, message []byte) protocol.StartFunc {
	startFunc, _ := s.backend.Sign(config, signers, message)
	return startFunc
}

// Refresh updates shares without changing the key
func (s *Suite) Refresh(config protocol.ThresholdConfig) protocol.StartFunc {
	startFunc, _ := s.backend.Refresh(config)
	return startFunc
}

// ConfigAdapter wraps any config to implement ThresholdConfig
type ConfigAdapter struct {
	*config.Config
}

// GetID returns the party ID
func (c *ConfigAdapter) GetID() party.ID { return c.ID }

// GetThreshold returns the threshold
func (c *ConfigAdapter) GetThreshold() int { return c.Threshold }

// GetGroup returns the curve group
func (c *ConfigAdapter) GetGroup() curve.Curve { return c.Group }

// GetPrivateShare returns the private share
func (c *ConfigAdapter) GetPrivateShare() curve.Scalar { return c.ECDSA }

// GetPublicKey returns the public key
func (c *ConfigAdapter) GetPublicKey() (curve.Point, error) {
	return c.Config.PublicKey()
}

// GetPublicShare returns a party's public share
func (c *ConfigAdapter) GetPublicShare(id party.ID) (curve.Point, error) {
	if pub, ok := c.Public[id]; ok && pub != nil {
		return pub.ECDSA, nil
	}
	return nil, fmt.Errorf("public share for %s not found", id)
}

// GetChainKey returns the chain key
func (c *ConfigAdapter) GetChainKey() []byte { return c.ChainKey }

// GetRID returns the RID
func (c *ConfigAdapter) GetRID() []byte { return c.RID }

// Validate validates the config
func (c *ConfigAdapter) Validate() error { return c.Config.Validate() }

// IsCompatible checks compatibility with another config
func (c *ConfigAdapter) IsCompatible(other protocol.ThresholdConfig) bool {
	myPubKey, err1 := c.GetPublicKey()
	otherPubKey, err2 := other.GetPublicKey()
	return err1 == nil && err2 == nil && myPubKey.Equal(otherPubKey)
}

// WrapConfig converts protocol-specific configs to ThresholdConfig
func WrapConfig(result interface{}) protocol.ThresholdConfig {
	switch cfg := result.(type) {
	case *cmpconfig.Config:
		return adapters.NewCMPAdapter(cfg)
	case *frostconfig.Config:
		return adapters.NewFROSTAdapter(cfg)
	case *config.Config:
		return &ConfigAdapter{Config: cfg}
	case protocol.ThresholdConfig:
		return cfg
	default:
		return nil
	}
}

// Factory creates protocol instances
type Factory struct {
	pool *pool.Pool
}

// NewFactory creates a protocol factory
func NewFactory(pl *pool.Pool) *Factory {
	return &Factory{pool: pl}
}

// Create creates a protocol by type
func (f *Factory) Create(protocolType string) (protocol.ThresholdProtocol, error) {
	switch protocolType {
	case "cmp":
		return adapters.NewCMPProtocol(f.pool), nil
	case "frost":
		return adapters.NewFROSTProtocol(), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", protocolType)
	}
}

// Auto selects the best protocol for the signature scheme
func (f *Factory) Auto(scheme protocol.SignatureScheme) *Suite {
	switch scheme {
	case protocol.ECDSA:
		return WithCMP(f.pool)
	case protocol.Schnorr:
		return WithFROST(f.pool)
	default:
		return nil
	}
}