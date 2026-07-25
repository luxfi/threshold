// SPDX-License-Identifier: BSD-3-Clause

package protocols_test

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	gethabi "github.com/luxfi/geth/accounts/abi"
	gethcommon "github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/state"
	"github.com/luxfi/geth/core/tracing"
	gethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm/runtime"

	"github.com/luxfi/threshold/internal/test"
	tecdsa "github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
)

// safeABI is the slice of the Safe / SafeProxyFactory surface this proof
// drives. getTransactionHash is deliberately included: the digest a Safe
// expects its owners to sign is EIP-712 over a domain that binds the Safe's
// own address and chain id, and asking the deployed contract for it is the
// only way to be sure the test signs what the contract will check. A
// hand-rolled EIP-712 encoder that disagrees with the contract would make
// this test prove nothing.
const safeABI = `[
{"type":"function","name":"setup","stateMutability":"nonpayable","inputs":[
  {"name":"_owners","type":"address[]"},{"name":"_threshold","type":"uint256"},
  {"name":"to","type":"address"},{"name":"data","type":"bytes"},
  {"name":"fallbackHandler","type":"address"},{"name":"paymentToken","type":"address"},
  {"name":"payment","type":"uint256"},{"name":"paymentReceiver","type":"address"}],"outputs":[]},
{"type":"function","name":"getTransactionHash","stateMutability":"view","inputs":[
  {"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},
  {"name":"operation","type":"uint8"},{"name":"safeTxGas","type":"uint256"},
  {"name":"baseGas","type":"uint256"},{"name":"gasPrice","type":"uint256"},
  {"name":"gasToken","type":"address"},{"name":"refundReceiver","type":"address"},
  {"name":"_nonce","type":"uint256"}],"outputs":[{"name":"","type":"bytes32"}]},
{"type":"function","name":"execTransaction","stateMutability":"payable","inputs":[
  {"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},
  {"name":"operation","type":"uint8"},{"name":"safeTxGas","type":"uint256"},
  {"name":"baseGas","type":"uint256"},{"name":"gasPrice","type":"uint256"},
  {"name":"gasToken","type":"address"},{"name":"refundReceiver","type":"address"},
  {"name":"signatures","type":"bytes"}],"outputs":[{"name":"","type":"bool"}]},
{"type":"function","name":"nonce","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint256"}]},
{"type":"function","name":"getOwners","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address[]"}]},
{"type":"function","name":"getThreshold","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint256"}]},
{"type":"function","name":"isOwner","stateMutability":"view","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"bool"}]},
{"type":"function","name":"VERSION","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"string"}]},
{"type":"function","name":"createProxyWithNonce","stateMutability":"nonpayable","inputs":[
  {"name":"_singleton","type":"address"},{"name":"initializer","type":"bytes"},
  {"name":"saltNonce","type":"uint256"}],"outputs":[{"name":"proxy","type":"address"}]}
]`

// evmHarness runs the real luxfi/geth EVM interpreter over one persistent
// StateDB. Contract code is the actual deployed bytecode and every call is a
// real state transition, so a signature the Safe rejects fails this test.
//
// This deliberately drives core/vm rather than ethclient/simulated: in
// luxfi/geth v1.20.1 the simulated backend cannot be constructed at all.
// node.New calls conf.Logger.IsZero() on a nil interface, and past that,
// eth/backend.go:524 calls dnsdisc.NewClient(dnsdisc.Config{}) unconditionally
// — before its own len(EthDiscoveryURLs) > 0 guard — which panics on a nil
// logger inside withDefaults. Both are nil-interface method calls on zero
// configs.
//
// The tradeoff is honest and worth stating: there is no chain here, so there
// are no blocks and no transaction hashes. What is proved is exactly the
// contract-level claim — that the real SafeL2 bytecode accepts a 3-of-5
// threshold signature and moves value on it.
type evmHarness struct {
	t   *testing.T
	abi gethabi.ABI
	cfg *runtime.Config
}

func newEVMHarness(t *testing.T) *evmHarness {
	t.Helper()

	sdb, err := state.New(gethtypes.EmptyRootHash, state.NewDatabaseForTesting())
	require.NoError(t, err)

	deployer := gethcommon.HexToAddress("0x00000000000000000000000000000000deb10relay"[:42])
	sdb.SetBalance(deployer, uint256.MustFromDecimal("1000000000000000000000000"), tracing.BalanceChangeUnspecified)

	parsed, err := gethabi.JSON(strings.NewReader(safeABI))
	require.NoError(t, err)

	return &evmHarness{
		t:   t,
		abi: parsed,
		cfg: &runtime.Config{
			State:       sdb,
			Origin:      deployer,
			GasLimit:    30_000_000,
			BlockNumber: big.NewInt(1),
			Time:        1_700_000_000,
			Value:       big.NewInt(0),
		},
	}
}

// deploy publishes contract bytecode and returns its address.
func (h *evmHarness) deploy(name string) gethcommon.Address {
	h.t.Helper()
	raw, err := os.ReadFile("testdata/" + name + ".bin")
	require.NoError(h.t, err, "missing %s bytecode", name)
	code, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	require.NoError(h.t, err)

	h.cfg.Value = big.NewInt(0)
	_, addr, _, err := runtime.Create(code, h.cfg)
	require.NoError(h.t, err, "deploying %s reverted", name)
	require.NotEqual(h.t, gethcommon.Address{}, addr)
	return addr
}

// exec calls a contract and requires it to succeed, returning the return data.
func (h *evmHarness) exec(to gethcommon.Address, data []byte) []byte {
	h.t.Helper()
	out, err := h.tryExec(to, data)
	require.NoError(h.t, err, "call reverted")
	return out
}

// tryExec calls a contract and surfaces a revert as an error, for the
// negative cases where a revert is the expected outcome.
func (h *evmHarness) tryExec(to gethcommon.Address, data []byte) ([]byte, error) {
	h.t.Helper()
	h.cfg.Value = big.NewInt(0)
	out, _, err := runtime.Call(to, data, h.cfg)
	return out, err
}

// call is a read-only invocation. State changes are rolled back via a
// snapshot so a view call can never mutate the world.
func (h *evmHarness) call(to gethcommon.Address, data []byte) []byte {
	h.t.Helper()
	snap := h.cfg.State.Snapshot()
	defer h.cfg.State.RevertToSnapshot(snap)
	return h.exec(to, data)
}

// fund credits an account directly. Funding is not the claim under test, so
// it is done as a state edit rather than a transfer transaction.
func (h *evmHarness) fund(addr gethcommon.Address, wei *big.Int) {
	h.t.Helper()
	h.cfg.State.SetBalance(addr, uint256.MustFromBig(wei), tracing.BalanceChangeUnspecified)
}

func (h *evmHarness) balance(addr gethcommon.Address) *big.Int {
	return h.cfg.State.GetBalance(addr).ToBig()
}

// TestQuorum3of5_CGGMP21_OperatesGnosisSafe is the custody proof that matters:
// a Safe whose only owner is a 3-of-5 CGGMP21 group key, executing a real
// value transfer authorised by three of the five shareholders.
//
// Nothing here is stubbed. The Safe is the real SafeL2 singleton bytecode
// behind the real SafeProxyFactory, running on a real EVM. The digest is the
// one the deployed Safe computes for itself. The signature comes from an
// actual distributed signing session — no party ever holds the whole key, and
// the two non-participating shareholders contribute nothing.
//
// If the group key were mis-derived, if the recovery id were wrong, if S were
// left high, or if the quorum were off by one, execTransaction would revert
// inside checkNSignatures and this test would fail. That is the whole reason
// to run it against the contract rather than against our own verifier.
func TestQuorum3of5_CGGMP21_OperatesGnosisSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("full CGGMP21 DKG plus EVM deployment; skipped under -short")
	}

	// --- 1. Real distributed key generation. No dealer, no full key anywhere.
	ids := test.PartyIDs(policy.N)
	pools := newPools(t, ids)
	configs, groupKey := keygen3of5(t, ids, pools, "safe/3of5/keygen")

	mpcAddr := gethcommon.BytesToAddress(func() []byte { a := evmAddress(t, groupKey); return a[:] }())
	t.Logf("3-of-5 CGGMP21 group address (the Safe's only owner): %s", mpcAddr.Hex())

	// --- 2. Real EVM, real Safe contracts.
	h := newEVMHarness(t)
	singleton := h.deploy("SafeL2")
	factory := h.deploy("SafeProxyFactory")
	t.Logf("SafeL2 singleton: %s   SafeProxyFactory: %s", singleton.Hex(), factory.Hex())

	version := new(string)
	require.NoError(t, h.abi.UnpackIntoInterface(version, "VERSION",
		h.call(singleton, mustPack(t, h.abi, "VERSION"))))
	t.Logf("Safe version: %s", *version)

	// --- 3. A brand-new Safe owned solely by the MPC group address.
	//
	// Threshold 1 here is the SAFE's owner count, not the MPC quorum: the Safe
	// has exactly one owner, and that owner is itself a 3-of-5 threshold key.
	// The 3-of-5 is enforced cryptographically inside the signing ceremony, so
	// the Safe cannot observe or weaken it.
	initializer := mustPack(t, h.abi, "setup",
		[]gethcommon.Address{mpcAddr}, // _owners
		big.NewInt(1),                 // _threshold
		gethcommon.Address{},          // to
		[]byte{},                      // data
		gethcommon.Address{},          // fallbackHandler
		gethcommon.Address{},          // paymentToken
		big.NewInt(0),                 // payment
		gethcommon.Address{},          // paymentReceiver
	)
	createCall := mustPack(t, h.abi, "createProxyWithNonce", singleton, initializer, big.NewInt(0))

	// Read the proxy address off an eth_call first, then actually create it.
	var safeAddr gethcommon.Address
	require.NoError(t, h.abi.UnpackIntoInterface(&safeAddr, "createProxyWithNonce", h.call(factory, createCall)))
	h.exec(factory, createCall)
	t.Logf("throwaway Safe deployed: %s", safeAddr.Hex())

	// The Safe must really be owned by the MPC address and nothing else.
	var owners []gethcommon.Address
	require.NoError(t, h.abi.UnpackIntoInterface(&owners, "getOwners", h.call(safeAddr, mustPack(t, h.abi, "getOwners"))))
	require.Equal(t, []gethcommon.Address{mpcAddr}, owners, "the Safe's owner set must be exactly the MPC group address")

	isOwner := new(bool)
	require.NoError(t, h.abi.UnpackIntoInterface(isOwner, "isOwner", h.call(safeAddr, mustPack(t, h.abi, "isOwner", mpcAddr))))
	require.True(t, *isOwner)

	// --- 4. Fund the Safe, then move value out of it under MPC authority.
	fundAmount := new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18))
	h.fund(safeAddr, fundAmount)

	require.Equal(t, 0, h.balance(safeAddr).Cmp(fundAmount), "Safe should hold the funded amount")

	recipient := gethcommon.HexToAddress("0x000000000000000000000000000000000000d00d")
	transfer := new(big.Int).Mul(big.NewInt(3), big.NewInt(1e18))

	// --- 5. Ask the Safe itself what digest its owner must sign.
	safeTxHashRaw := h.call(safeAddr, mustPack(t, h.abi, "getTransactionHash",
		recipient, transfer, []byte{}, uint8(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0),
		gethcommon.Address{}, gethcommon.Address{}, big.NewInt(0)))
	var safeTxHash [32]byte
	require.NoError(t, h.abi.UnpackIntoInterface(&safeTxHash, "getTransactionHash", safeTxHashRaw))
	t.Logf("safeTxHash to be threshold-signed: 0x%x", safeTxHash)

	// --- 6. Three of the five shareholders sign it. Two sit the round out.
	signers := ids[:policy.K]
	t.Logf("signing parties: %v (of %v)", signers, ids)

	sigResults, err := test.RunProtocolWithTimeout(t, signers, []byte("safe/3of5/sign"), cggmpTimeout,
		func(id party.ID) protocol.StartFunc {
			return cmp.Sign(configs[id], signers, safeTxHash[:], pools[id])
		})
	require.NoError(t, err, "the 3-of-5 signing ceremony must complete")

	sig := sigResults[signers[0]].(*tecdsa.Signature)
	require.True(t, sig.Verify(groupKey, safeTxHash[:]), "signature must verify under the group key")
	require.Equal(t, mpcAddr, gethcommon.BytesToAddress(func() []byte {
		a := recoverAddress(t, safeTxHash[:], sig)
		return a[:]
	}()), "signature must recover to the Safe's owner")

	eth, err := sig.SigEthereum()
	require.NoError(t, err)

	// Safe's checkNSignatures reads v in {27,28} for a plain ECDSA owner
	// signature; SigEthereum emits the raw recovery id 0/1.
	safeSig := make([]byte, 65)
	copy(safeSig, eth)
	safeSig[64] = eth[64] + 27

	// --- 7. Execute. The Safe verifies the signature itself.
	execCall := mustPack(t, h.abi, "execTransaction",
		recipient, transfer, []byte{}, uint8(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0),
		gethcommon.Address{}, gethcommon.Address{}, safeSig)

	execOut, err := h.tryExec(safeAddr, execCall)
	require.NoError(t, err, "execTransaction reverted — the Safe rejected the 3-of-5 signature")
	success := new(bool)
	require.NoError(t, h.abi.UnpackIntoInterface(success, "execTransaction", execOut))
	require.True(t, *success, "execTransaction returned false")
	t.Log("execTransaction SUCCEEDED — the Safe accepted a signature produced by 3 of 5 parties")

	// --- 8. The money actually moved, and the Safe advanced its nonce.
	require.Equal(t, 0, h.balance(recipient).Cmp(transfer),
		"recipient must have received the transfer authorised by 3 of 5 parties")

	require.Equal(t, 0, h.balance(safeAddr).Cmp(new(big.Int).Sub(fundAmount, transfer)), "Safe balance must be debited")

	safeNonce := new(big.Int)
	require.NoError(t, h.abi.UnpackIntoInterface(&safeNonce, "nonce", h.call(safeAddr, mustPack(t, h.abi, "nonce"))))
	require.Equal(t, int64(1), safeNonce.Int64(), "Safe nonce must advance after a successful execTransaction")

	// --- 9. NEGATIVE: replaying the same signature must fail. The nonce is
	// bound into safeTxHash, so the old signature no longer authorises
	// anything — this is what stops a captured signature being reused.
	_, err = h.tryExec(safeAddr, execCall)
	require.Error(t, err, "replaying a spent Safe signature must be rejected")
	t.Logf("replay correctly rejected: %v", err)
}

// TestQuorum3of5_CGGMP21_SafeRejectsSubQuorumSignature is the negative that
// closes the loop at the contract boundary: a signature produced by a
// DIFFERENT 3-of-5 group (standing in for any key that is not the owner) is
// refused by the Safe.
//
// The two-signers-cannot-sign case is proved cryptographically in
// TestQuorum3of5_CGGMP21_TwoSignersCannotSign — the protocol refuses to emit a
// signature at all, so there is nothing to hand to a Safe. What remains to
// prove here is that the Safe checks WHICH key signed, not merely that some
// well-formed signature was supplied.
func TestQuorum3of5_CGGMP21_SafeRejectsForeignSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("two full CGGMP21 DKGs plus EVM deployment; skipped under -short")
	}

	ids := test.PartyIDs(policy.N)
	pools := newPools(t, ids)

	// The real owner key, and an unrelated key generated the same way.
	ownerConfigs, ownerKey := keygen3of5(t, ids, pools, "safe/3of5/owner-keygen")
	_ = ownerConfigs
	foreignConfigs, foreignKey := keygen3of5(t, ids, pools, "safe/3of5/foreign-keygen")
	require.False(t, ownerKey.Equal(foreignKey), "the two DKGs must produce different keys")

	ownerAddr := gethcommon.BytesToAddress(func() []byte { a := evmAddress(t, ownerKey); return a[:] }())

	h := newEVMHarness(t)
	singleton := h.deploy("SafeL2")
	factory := h.deploy("SafeProxyFactory")

	initializer := mustPack(t, h.abi, "setup",
		[]gethcommon.Address{ownerAddr}, big.NewInt(1),
		gethcommon.Address{}, []byte{}, gethcommon.Address{},
		gethcommon.Address{}, big.NewInt(0), gethcommon.Address{})
	createCall := mustPack(t, h.abi, "createProxyWithNonce", singleton, initializer, big.NewInt(0))

	var safeAddr gethcommon.Address
	require.NoError(t, h.abi.UnpackIntoInterface(&safeAddr, "createProxyWithNonce", h.call(factory, createCall)))
	h.exec(factory, createCall)
	h.fund(safeAddr, new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18)))

	recipient := gethcommon.HexToAddress("0x000000000000000000000000000000000000dead")
	transfer := big.NewInt(1e18)

	safeTxHashRaw := h.call(safeAddr, mustPack(t, h.abi, "getTransactionHash",
		recipient, transfer, []byte{}, uint8(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0),
		gethcommon.Address{}, gethcommon.Address{}, big.NewInt(0)))
	var safeTxHash [32]byte
	require.NoError(t, h.abi.UnpackIntoInterface(&safeTxHash, "getTransactionHash", safeTxHashRaw))

	// A perfectly valid signature — from the wrong key.
	signers := ids[:policy.K]
	sigResults, err := test.RunProtocolWithTimeout(t, signers, []byte("safe/3of5/foreign-sign"), cggmpTimeout,
		func(id party.ID) protocol.StartFunc {
			return cmp.Sign(foreignConfigs[id], signers, safeTxHash[:], pools[id])
		})
	require.NoError(t, err)
	sig := sigResults[signers[0]].(*tecdsa.Signature)
	require.True(t, sig.Verify(foreignKey, safeTxHash[:]), "the foreign signature is itself valid")

	eth, err := sig.SigEthereum()
	require.NoError(t, err)
	safeSig := make([]byte, 65)
	copy(safeSig, eth)
	safeSig[64] = eth[64] + 27

	execCall := mustPack(t, h.abi, "execTransaction",
		recipient, transfer, []byte{}, uint8(0),
		big.NewInt(0), big.NewInt(0), big.NewInt(0),
		gethcommon.Address{}, gethcommon.Address{}, safeSig)

	_, err = h.tryExec(safeAddr, execCall)
	require.Error(t, err, "the Safe must reject a valid signature from a key that is not its owner")
	t.Logf("Safe correctly rejected a foreign 3-of-5 signature: %v", err)
}

func mustPack(t *testing.T, abi gethabi.ABI, name string, args ...interface{}) []byte {
	t.Helper()
	packed, err := abi.Pack(name, args...)
	require.NoError(t, err, "pack %s", name)
	return packed
}
