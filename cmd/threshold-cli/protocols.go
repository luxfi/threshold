package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/taproot"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/lss"
)

// LSS Protocol implementations

func runLSSKeygen(group curve.Curve, selfID party.ID, partyIDs []party.ID, threshold int, pl *pool.Pool, network *test.Network) (*lss.Config, error) {
	h, err := protocol.NewMultiHandler(lss.Keygen(group, selfID, partyIDs, threshold, pl), nil)
	if err != nil {
		return nil, err
	}

	// Run protocol in goroutine
	done := make(chan error)
	go func() {
		test.HandlerLoop(selfID, h, network)
		done <- nil
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		return result.(*lss.Config), nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("keygen timeout")
	}
}

func runLSSSign(config *lss.Config, signers []party.ID, message []byte, pl *pool.Pool, network *test.Network) (*ecdsa.Signature, error) {
	// Hash the message
	hash := sha256.Sum256(message)
	
	h, err := protocol.NewMultiHandler(lss.Sign(config, signers, hash[:], pl), nil)
	if err != nil {
		return nil, err
	}

	done := make(chan error)
	go func() {
		test.HandlerLoop(config.ID, h, network)
		done <- nil
	}()

	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		return result.(*ecdsa.Signature), nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("signing timeout")
	}
}

func runLSSReshare(config *lss.Config, newThreshold int, newParties []party.ID, pl *pool.Pool, network *test.Network) (*lss.Config, error) {
	if newThreshold == 0 {
		newThreshold = config.Threshold
	}

	h, err := protocol.NewMultiHandler(lss.Reshare(config, newThreshold, newParties, pl), nil)
	if err != nil {
		return nil, err
	}

	done := make(chan error)
	go func() {
		test.HandlerLoop(config.ID, h, network)
		done <- nil
	}()

	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		return result.(*lss.Config), nil
	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("reshare timeout")
	}
}

// CMP Protocol implementations

func runCMPKeygen(group curve.Curve, selfID party.ID, partyIDs []party.ID, threshold int, pl *pool.Pool, network *test.Network) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(group, selfID, partyIDs, threshold, pl), nil)
	if err != nil {
		return nil, err
	}

	done := make(chan error)
	go func() {
		test.HandlerLoop(selfID, h, network)
		done <- nil
	}()

	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		return result.(*cmp.Config), nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("keygen timeout")
	}
}

func runCMPSign(config *cmp.Config, signers []party.ID, message []byte, pl *pool.Pool, network *test.Network) (*ecdsa.Signature, error) {
	// For CMP, we need to run presign first
	h, err := protocol.NewMultiHandler(cmp.Presign(config, signers, pl), nil)
	if err != nil {
		return nil, err
	}

	done := make(chan error)
	go func() {
		test.HandlerLoop(config.ID, h, network)
		done <- nil
	}()

	var presignResult *ecdsa.PreSignature
	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		presignResult = result.(*ecdsa.PreSignature)
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("presign timeout")
	}

	// Now run actual signing
	hash := sha256.Sum256(message)
	h, err = protocol.NewMultiHandler(cmp.PresignOnline(config, presignResult, hash[:], pl), nil)
	if err != nil {
		return nil, err
	}

	done = make(chan error)
	go func() {
		test.HandlerLoop(config.ID, h, network)
		done <- nil
	}()

	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		return result.(*ecdsa.Signature), nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("signing timeout")
	}
}

// FROST Protocol implementations

func runFROSTKeygen(group curve.Curve, selfID party.ID, partyIDs []party.ID, threshold int, pl *pool.Pool, network *test.Network) (*frost.Config, error) {
	h, err := protocol.NewMultiHandler(frost.Keygen(group, selfID, partyIDs, threshold, pl), nil)
	if err != nil {
		return nil, err
	}

	done := make(chan error)
	go func() {
		test.HandlerLoop(selfID, h, network)
		done <- nil
	}()

	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		return result.(*frost.Config), nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("keygen timeout")
	}
}

func runFROSTSign(config *frost.Config, signers []party.ID, message []byte, pl *pool.Pool, network *test.Network) (*taproot.Signature, error) {
	h, err := protocol.NewMultiHandler(frost.Sign(config, signers, message, pl), nil)
	if err != nil {
		return nil, err
	}

	done := make(chan error)
	go func() {
		test.HandlerLoop(config.ID, h, network)
		done <- nil
	}()

	select {
	case <-done:
		result, err := h.Result()
		if err != nil {
			return nil, err
		}
		return result.(*taproot.Signature), nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("signing timeout")
	}
}

// Verification functions

func verifyECDSA(sigData, pkData, message []byte) (bool, error) {
	var sig ecdsa.Signature
	if err := json.Unmarshal(sigData, &sig); err != nil {
		return false, fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	// Parse public key (assuming hex encoded X coordinate)
	pkHex := string(pkData)
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Reconstruct public key point
	group := curve.Secp256k1{}
	publicKey := group.NewPoint()
	if err := publicKey.UnmarshalBinary(pkBytes); err != nil {
		return false, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Hash message and verify
	hash := sha256.Sum256(message)
	return sig.Verify(publicKey, hash[:]), nil
}

func verifySchnorr(sigData, pkData, message []byte) (bool, error) {
	var sig taproot.Signature
	if err := json.Unmarshal(sigData, &sig); err != nil {
		return false, fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	// Parse public key
	pkHex := string(pkData)
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Reconstruct public key point
	group := curve.Secp256k1{}
	publicKey := group.NewPoint()
	if err := publicKey.UnmarshalBinary(pkBytes); err != nil {
		return false, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	return sig.Verify(publicKey, message), nil
}

// Export functions

func exportLSSConfig(config *lss.Config, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(config, "", "  ")
	case "pem":
		// Export as PEM format
		return exportToPEM("LSS PRIVATE KEY", config)
	case "der":
		// Export as DER format
		return exportToDER(config)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

func exportCMPConfig(config *cmp.Config, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(config, "", "  ")
	case "pem":
		return exportToPEM("CMP PRIVATE KEY", config)
	case "der":
		return exportToDER(config)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

func exportFROSTConfig(config *frost.Config, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(config, "", "  ")
	case "pem":
		return exportToPEM("FROST PRIVATE KEY", config)
	case "der":
		return exportToDER(config)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// Import functions

func importLSSConfig(data []byte, format string) (*lss.Config, error) {
	var config lss.Config
	
	switch format {
	case "json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, err
		}
	case "pem":
		if err := importFromPEM(data, &config); err != nil {
			return nil, err
		}
	case "der":
		if err := importFromDER(data, &config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
	
	return &config, nil
}

func importCMPConfig(data []byte, format string) (*cmp.Config, error) {
	var config cmp.Config
	
	switch format {
	case "json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, err
		}
	case "pem":
		if err := importFromPEM(data, &config); err != nil {
			return nil, err
		}
	case "der":
		if err := importFromDER(data, &config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
	
	return &config, nil
}

func importFROSTConfig(data []byte, format string) (*frost.Config, error) {
	var config frost.Config
	
	switch format {
	case "json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, err
		}
	case "pem":
		if err := importFromPEM(data, &config); err != nil {
			return nil, err
		}
	case "der":
		if err := importFromDER(data, &config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
	
	return &config, nil
}

// Helper functions for import/export

func exportToPEM(keyType string, config interface{}) ([]byte, error) {
	// This is a simplified implementation
	// In production, you'd use proper PEM encoding
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	
	pem := fmt.Sprintf("-----BEGIN %s-----\n", keyType)
	pem += hex.EncodeToString(data)
	pem += fmt.Sprintf("\n-----END %s-----\n", keyType)
	
	return []byte(pem), nil
}

func exportToDER(config interface{}) ([]byte, error) {
	// This is a simplified implementation
	// In production, you'd use proper DER/ASN.1 encoding
	return json.Marshal(config)
}

func importFromPEM(data []byte, config interface{}) error {
	// This is a simplified implementation
	// Extract hex data between BEGIN and END markers
	str := string(data)
	start := strings.Index(str, "-----") + 5
	start = strings.Index(str[start:], "\n") + start + 1
	end := strings.LastIndex(str, "-----")
	
	hexData := strings.TrimSpace(str[start:end])
	jsonData, err := hex.DecodeString(hexData)
	if err != nil {
		return err
	}
	
	return json.Unmarshal(jsonData, config)
}

func importFromDER(data []byte, config interface{}) error {
	// This is a simplified implementation
	return json.Unmarshal(data, config)
}