package ecdsa

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cronokirby/saferith"
	luxcrypto "github.com/luxfi/crypto"
	gethcommon "github.com/luxfi/geth/common"
	gethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/ethclient"
	"github.com/luxfi/threshold/pkg/math/curve"
)

// TestSigEthereum_LandsEVMTxOnDevnet is the live end-to-end proof that a
// signature emitted through SigEthereum — the exact helper the mpcd signing
// sessions and KMS /sign now use — is accepted as a real transaction by a
// luxfi/evm node. It signs an EIP-155 legacy tx with the deployer key via
// SigEthereum, recovers the sender locally, broadcasts it, and asserts the
// receipt lands successfully. EIP-155 (chainID-protected) is used because Lux
// rejects unprotected pre-155 txs — the very reason the KMS sig format matters.
//
// Gated on env so a CI box without a node skips cleanly:
//
//	LUX_DEVNET_RPC  e.g. http://localhost:8545/v1/chain/C/rpc
//	LUX_DEVNET_PK   deployer private key (hex, 0x optional), funded on-chain
func TestSigEthereum_LandsEVMTxOnDevnet(t *testing.T) {
	rpc := os.Getenv("LUX_DEVNET_RPC")
	pkHex := strings.TrimPrefix(os.Getenv("LUX_DEVNET_PK"), "0x")
	if rpc == "" || pkHex == "" {
		t.Skip("set LUX_DEVNET_RPC and LUX_DEVNET_PK to run the live devnet proof")
	}
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil || len(pkBytes) != 32 {
		t.Fatalf("LUX_DEVNET_PK must be 32-byte hex: %v", err)
	}

	// The same key in two representations: a geth ECDSA key (for the address
	// the EVM will recover to) and a threshold scalar (for SigEthereum signing).
	gethKey, err := luxcrypto.ToECDSA(pkBytes)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	// luxfi/crypto carries its own common.Address type distinct from geth's;
	// bridge by raw bytes so the tx/signer path stays in geth's type world.
	from := gethcommon.BytesToAddress(luxcrypto.PubkeyToAddress(gethKey.PublicKey).Bytes())

	group := curve.Secp256k1{}
	x := group.NewScalar().SetNat(new(saferith.Nat).SetBytes(pkBytes))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		t.Fatalf("dial %s: %v", rpc, err)
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		t.Fatalf("chainID: %v", err)
	}
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		t.Fatalf("gasPrice: %v", err)
	}

	// 0-value self-transfer: the minimal landing tx, so the ONLY thing under
	// test is signature acceptance (no balance/state dependence beyond gas).
	tx := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    nonce,
		To:       &from,
		Value:    big.NewInt(0),
		Gas:      21000,
		GasPrice: gasPrice,
	})
	signer := gethtypes.LatestSignerForChainID(chainID)
	h := signer.Hash(tx)

	// Sign the EIP-155 signing hash via the SAME helper mpcd/KMS emit through.
	// SigEthereum returns R.x‖S(low)‖V with V in {0,1}, exactly what
	// WithSignature expects.
	sig := NewSignature(x, h.Bytes(), nil)
	eth, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("SigEthereum: %v", err)
	}

	signedTx, err := tx.WithSignature(signer, eth)
	if err != nil {
		t.Fatalf("WithSignature: %v", err)
	}

	// The signature must recover to the signer locally (ecrecover) BEFORE
	// broadcast — this is precisely what the node checks to admit the tx.
	if got, err := gethtypes.Sender(signer, signedTx); err != nil || got != from {
		t.Fatalf("local Sender = %s (err %v), want %s", got.Hex(), err, from.Hex())
	}

	// ...and the node must accept and mine it.
	if err := client.SendTransaction(ctx, signedTx); err != nil {
		t.Fatalf("node REJECTED the SigEthereum-signed tx: %v", err)
	}
	t.Logf("broadcast %s from %s (nonce %d, chainID %s)", signedTx.Hash().Hex(), from.Hex(), nonce, chainID)

	var receipt *gethtypes.Receipt
	for i := 0; i < 60; i++ {
		receipt, err = client.TransactionReceipt(ctx, signedTx.Hash())
		if err == nil && receipt != nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if receipt == nil {
		t.Fatalf("no receipt after 30s for %s", signedTx.Hash().Hex())
	}
	if receipt.Status != gethtypes.ReceiptStatusSuccessful {
		t.Fatalf("tx mined but FAILED: status=%d", receipt.Status)
	}
	t.Logf("SigEthereum-signed tx MINED in block %d, status=success", receipt.BlockNumber.Uint64())
}
