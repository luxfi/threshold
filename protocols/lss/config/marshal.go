package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/luxfi/threshold/pkg/party"
)

type configJSON struct {
	ID         string                       `json:"id"`
	Threshold  int                          `json:"threshold"`
	Generation uint64                       `json:"generation"`
	ECDSA      string                       `json:"ecdsa"`  // Base64 encoded
	Public     map[string]*publicJSON       `json:"public"`
	ChainKey   string                       `json:"chain_key"` // Base64 encoded
	RID        string                       `json:"rid"`       // Base64 encoded
}

type publicJSON struct {
	ECDSA string `json:"ecdsa"` // Base64 encoded
}

// MarshalJSON implements json.Marshaler
func (c *Config) MarshalJSON() ([]byte, error) {
	// Marshal ECDSA share
	ecdsaBytes, err := c.ECDSA.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA share: %w", err)
	}
	
	// Marshal public shares
	public := make(map[string]*publicJSON, len(c.Public))
	for id, p := range c.Public {
		pubBytes, err := p.ECDSA.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public ECDSA for %s: %w", id, err)
		}
		public[string(id)] = &publicJSON{
			ECDSA: base64.StdEncoding.EncodeToString(pubBytes),
		}
	}
	
	out := &configJSON{
		ID:         string(c.ID),
		Threshold:  c.Threshold,
		Generation: c.Generation,
		ECDSA:      base64.StdEncoding.EncodeToString(ecdsaBytes),
		Public:     public,
		ChainKey:   base64.StdEncoding.EncodeToString(c.ChainKey),
		RID:        base64.StdEncoding.EncodeToString(c.RID),
	}
	
	return json.Marshal(out)
}

// UnmarshalJSON implements json.Unmarshaler
func (c *Config) UnmarshalJSON(data []byte) error {
	if c.Group == nil {
		return fmt.Errorf("lss/config: group must be set before unmarshalling")
	}
	
	var out configJSON
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	
	c.ID = party.ID(out.ID)
	c.Threshold = out.Threshold
	c.Generation = out.Generation
	
	// Unmarshal ChainKey
	chainKey, err := base64.StdEncoding.DecodeString(out.ChainKey)
	if err != nil {
		return fmt.Errorf("lss/config: failed to decode chain key: %w", err)
	}
	c.ChainKey = chainKey
	
	// Unmarshal RID
	rid, err := base64.StdEncoding.DecodeString(out.RID)
	if err != nil {
		return fmt.Errorf("lss/config: failed to decode RID: %w", err)
	}
	c.RID = rid
	
	// Unmarshal ECDSA share
	ecdsaBytes, err := base64.StdEncoding.DecodeString(out.ECDSA)
	if err != nil {
		return fmt.Errorf("lss/config: failed to decode ECDSA share: %w", err)
	}
	ecdsa := c.Group.NewScalar()
	if err := ecdsa.UnmarshalBinary(ecdsaBytes); err != nil {
		return fmt.Errorf("lss/config: failed to unmarshal ECDSA share: %w", err)
	}
	c.ECDSA = ecdsa
	
	// Unmarshal public shares
	c.Public = make(map[party.ID]*Public, len(out.Public))
	for idStr, p := range out.Public {
		id := party.ID(idStr)
		
		pubBytes, err := base64.StdEncoding.DecodeString(p.ECDSA)
		if err != nil {
			return fmt.Errorf("lss/config: failed to decode public ECDSA for %s: %w", id, err)
		}
		
		ecdsaPoint := c.Group.NewPoint()
		if err := ecdsaPoint.UnmarshalBinary(pubBytes); err != nil {
			return fmt.Errorf("lss/config: failed to unmarshal ECDSA public for %s: %w", id, err)
		}
		
		c.Public[id] = &Public{
			ECDSA: ecdsaPoint,
		}
	}
	
	return nil
}