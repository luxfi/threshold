package frost_test

import (
	"fmt"
	"testing"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSR25519KeygenAndSign(t *testing.T) {
	N := 3
	T := 1 // threshold=1 means 2-of-3

	partyIDs := test.PartyIDs(N)

	// Step 1: Run keygen over Ristretto255
	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("sr25519-keygen"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenSR25519(id, partyIDs, T)
	})
	require.NoError(t, err, "keygen should complete without error")
	require.Len(t, keygenResults, N, "all parties should have keygen results")

	// Verify all parties agree on the public key
	configs := make(map[party.ID]*frost.Config, N)
	var firstPubKey curve.Point
	for id, result := range keygenResults {
		config, ok := result.(*frost.Config)
		require.True(t, ok, "result should be *frost.Config for party %s", id)
		require.NotNil(t, config)
		require.NotNil(t, config.PublicKey)
		require.Equal(t, "ristretto255", config.PublicKey.Curve().Name())
		configs[id] = config

		if firstPubKey == nil {
			firstPubKey = config.PublicKey
		} else {
			assert.True(t, firstPubKey.Equal(config.PublicKey),
				"all parties should have the same public key")
		}
	}

	// Step 2: Sign with T+1 parties
	signers := partyIDs[:T+1]
	message := []byte("hello substrate")
	signingContext := []byte("substrate")

	signResults, err := test.RunProtocol(t, signers, []byte("sr25519-sign"), func(id party.ID) protocol.StartFunc {
		return frost.SignSR25519(configs[id], signers, signingContext, message)
	})
	require.NoError(t, err, "signing should complete without error")
	require.Len(t, signResults, len(signers), "all signers should have results")

	// Step 3: Verify all signers produced the same signature
	var firstSig *frost.SR25519Signature
	for id, result := range signResults {
		sig, ok := result.(frost.SR25519Signature)
		require.True(t, ok, "result should be frost.SR25519Signature for party %s, got %T", id, result)
		if firstSig == nil {
			firstSig = &sig
		} else {
			assert.Equal(t, firstSig.Data, sig.Data, "all signers should produce the same signature")
		}
	}
	require.NotNil(t, firstSig)

	// Step 4: CRITICAL -- cross-verify with go-schnorrkel
	// This proves our threshold-produced signature is compatible with
	// the standard sr25519 verifier used in Substrate/Polkadot.
	pubKeyBytes, err := firstPubKey.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, pubKeyBytes, 32, "ristretto255 public key should be 32 bytes")

	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKeyBytes)
	schnorrkelPub, err := schnorrkel.NewPublicKey(pubKeyArr)
	require.NoError(t, err, "go-schnorrkel should accept our public key")

	schnorrkelSig := new(schnorrkel.Signature)
	err = schnorrkelSig.Decode(firstSig.Data)
	require.NoError(t, err, "go-schnorrkel should accept our signature encoding")

	// Build the signing transcript the same way go-schnorrkel does
	transcript := schnorrkel.NewSigningContext(signingContext, message)
	ok, err := schnorrkelPub.Verify(schnorrkelSig, transcript)
	require.NoError(t, err, "verification should not error")
	assert.True(t, ok, "threshold sr25519 signature must verify against standard go-schnorrkel verifier")

	t.Logf("sr25519 cross-verification passed: threshold %d-of-%d signature verified by go-schnorrkel", T+1, N)
}

func TestSR25519KeygenAndSign3of5(t *testing.T) {
	N := 5
	T := 2 // threshold=2 means 3-of-5

	partyIDs := test.PartyIDs(N)

	// Keygen
	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("sr25519-keygen-3of5"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenSR25519(id, partyIDs, T)
	})
	require.NoError(t, err)
	require.Len(t, keygenResults, N)

	configs := make(map[party.ID]*frost.Config, N)
	var pubKey curve.Point
	for id, result := range keygenResults {
		config := result.(*frost.Config)
		configs[id] = config
		if pubKey == nil {
			pubKey = config.PublicKey
		}
	}

	// Sign with T+1 parties
	signers := partyIDs[:T+1]
	message := []byte("polkadot transfer 100 DOT")
	signingContext := []byte("substrate")

	signResults, err := test.RunProtocol(t, signers, []byte("sr25519-sign-3of5"), func(id party.ID) protocol.StartFunc {
		return frost.SignSR25519(configs[id], signers, signingContext, message)
	})
	require.NoError(t, err)
	require.Len(t, signResults, len(signers))

	// Get signature
	var sig frost.SR25519Signature
	for _, result := range signResults {
		sig = result.(frost.SR25519Signature)
		break
	}

	// Cross-verify with go-schnorrkel
	pubKeyBytes, _ := pubKey.MarshalBinary()
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKeyBytes)
	schnorrkelPub, err := schnorrkel.NewPublicKey(pubKeyArr)
	require.NoError(t, err)

	schnorrkelSig := new(schnorrkel.Signature)
	require.NoError(t, schnorrkelSig.Decode(sig.Data))

	transcript := schnorrkel.NewSigningContext(signingContext, message)
	ok, err := schnorrkelPub.Verify(schnorrkelSig, transcript)
	require.NoError(t, err)
	assert.True(t, ok, "3-of-5 threshold sr25519 signature must verify")

	t.Logf("sr25519 3-of-5 cross-verification passed")
}

func TestSR25519DifferentSignerSubsets(t *testing.T) {
	N := 5
	T := 2

	partyIDs := test.PartyIDs(N)

	// Keygen
	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("sr25519-keygen-subsets"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenSR25519(id, partyIDs, T)
	})
	require.NoError(t, err)

	configs := make(map[party.ID]*frost.Config, N)
	var pubKey curve.Point
	for id, result := range keygenResults {
		configs[id] = result.(*frost.Config)
		if pubKey == nil {
			pubKey = result.(*frost.Config).PublicKey
		}
	}

	// Sign with different subsets
	subsets := [][]party.ID{
		partyIDs[:T+1],    // first T+1
		partyIDs[1 : T+2], // middle T+1
		partyIDs[N-T-1:],  // last T+1
	}

	message := []byte("test different subsets")
	signingContext := []byte("substrate")

	for i, signers := range subsets {
		t.Run(fmt.Sprintf("subset_%d", i), func(t *testing.T) {
			signResults, err := test.RunProtocol(t, signers, []byte(fmt.Sprintf("sr25519-sign-subset-%d", i)), func(id party.ID) protocol.StartFunc {
				return frost.SignSR25519(configs[id], signers, signingContext, message)
			})
			require.NoError(t, err)
			require.Len(t, signResults, len(signers))

			var sig frost.SR25519Signature
			for _, result := range signResults {
				sig = result.(frost.SR25519Signature)
				break
			}

			// Cross-verify
			pubKeyBytes, _ := pubKey.MarshalBinary()
			var pubKeyArr [32]byte
			copy(pubKeyArr[:], pubKeyBytes)
			schnorrkelPub, _ := schnorrkel.NewPublicKey(pubKeyArr)

			schnorrkelSig := new(schnorrkel.Signature)
			require.NoError(t, schnorrkelSig.Decode(sig.Data))

			transcript := schnorrkel.NewSigningContext(signingContext, message)
			ok, err := schnorrkelPub.Verify(schnorrkelSig, transcript)
			require.NoError(t, err)
			assert.True(t, ok)
		})
	}
}

func TestSR25519CustomSigningContext(t *testing.T) {
	N := 3
	T := 1

	partyIDs := test.PartyIDs(N)

	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("sr25519-keygen-ctx"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenSR25519(id, partyIDs, T)
	})
	require.NoError(t, err)

	configs := make(map[party.ID]*frost.Config, N)
	var pubKey curve.Point
	for id, result := range keygenResults {
		configs[id] = result.(*frost.Config)
		if pubKey == nil {
			pubKey = result.(*frost.Config).PublicKey
		}
	}

	signers := partyIDs[:T+1]
	message := []byte("custom context message")
	customContext := []byte("my-custom-app-v1")

	signResults, err := test.RunProtocol(t, signers, []byte("sr25519-sign-ctx"), func(id party.ID) protocol.StartFunc {
		return frost.SignSR25519(configs[id], signers, customContext, message)
	})
	require.NoError(t, err)

	var sig frost.SR25519Signature
	for _, result := range signResults {
		sig = result.(frost.SR25519Signature)
		break
	}

	// Cross-verify with the custom context
	pubKeyBytes, _ := pubKey.MarshalBinary()
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKeyBytes)
	schnorrkelPub, _ := schnorrkel.NewPublicKey(pubKeyArr)

	schnorrkelSig := new(schnorrkel.Signature)
	require.NoError(t, schnorrkelSig.Decode(sig.Data))

	// Must use the same custom context for verification
	transcript := schnorrkel.NewSigningContext(customContext, message)
	ok, err := schnorrkelPub.Verify(schnorrkelSig, transcript)
	require.NoError(t, err)
	assert.True(t, ok, "signature with custom context must verify")

	// Verify it does NOT verify with wrong context
	wrongTranscript := schnorrkel.NewSigningContext([]byte("wrong-context"), message)
	schnorrkelSig2 := new(schnorrkel.Signature)
	require.NoError(t, schnorrkelSig2.Decode(sig.Data))
	ok2, _ := schnorrkelPub.Verify(schnorrkelSig2, wrongTranscript)
	assert.False(t, ok2, "signature must NOT verify with wrong context")
}

// TestSR25519VerifyInternalConsistency verifies that the SR25519Signature.Verify
// method works correctly by itself (separate from go-schnorrkel cross-verification).
func TestSR25519VerifyInternalConsistency(t *testing.T) {
	N := 3
	T := 1

	partyIDs := test.PartyIDs(N)

	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("sr25519-keygen-internal"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenSR25519(id, partyIDs, T)
	})
	require.NoError(t, err)

	configs := make(map[party.ID]*frost.Config, N)
	var pubKey curve.Point
	for id, result := range keygenResults {
		configs[id] = result.(*frost.Config)
		if pubKey == nil {
			pubKey = result.(*frost.Config).PublicKey
		}
	}

	signers := partyIDs[:T+1]
	message := []byte("internal verify test")
	signingContext := []byte("substrate")

	signResults, err := test.RunProtocol(t, signers, []byte("sr25519-sign-internal"), func(id party.ID) protocol.StartFunc {
		return frost.SignSR25519(configs[id], signers, signingContext, message)
	})
	require.NoError(t, err)

	for id, result := range signResults {
		sig := result.(frost.SR25519Signature)
		ok := sig.Verify(pubKey, message)
		assert.True(t, ok, "internal verify should pass for party %s", id)
	}
}

// TestSR25519MerlinTranscriptLabels verifies that the Merlin transcript labels
// we use match exactly what go-schnorrkel/schnorrkel-rs produces.
func TestSR25519MerlinTranscriptLabels(t *testing.T) {
	// Create a transcript the same way go-schnorrkel does
	ctx := []byte("substrate")
	msg := []byte("test")

	t1 := schnorrkel.NewSigningContext(ctx, msg)
	// go-schnorrkel.NewSigningContext does:
	//   t = merlin.NewTranscript("SigningContext")
	//   t.AppendMessage([]byte(""), ctx)
	//   t.AppendMessage([]byte("sign-bytes"), msg)

	// Now replicate with raw merlin
	t2 := merlin.NewTranscript("SigningContext")
	t2.AppendMessage([]byte(""), ctx)
	t2.AppendMessage([]byte("sign-bytes"), msg)

	// Both transcripts should be in the same state.
	// To verify, we append the same additional messages and extract the same challenge.

	// Simulate what happens during signing:
	// Both get proto-name, sign:pk, sign:R, then extract sign:c
	pubBytes := make([]byte, 32) // zero public key for testing
	rBytes := r255.NewElement().Base().Encode(nil)

	t1.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
	t1.AppendMessage([]byte("sign:pk"), pubBytes)
	t1.AppendMessage([]byte("sign:R"), rBytes)
	c1 := t1.ExtractBytes([]byte("sign:c"), 64)

	t2.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
	t2.AppendMessage([]byte("sign:pk"), pubBytes)
	t2.AppendMessage([]byte("sign:R"), rBytes)
	c2 := t2.ExtractBytes([]byte("sign:c"), 64)

	assert.Equal(t, c1, c2, "challenge bytes from go-schnorrkel and raw merlin must match")
}
