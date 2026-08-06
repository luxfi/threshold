package sign

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rfc8032Vectors are the Ed25519 test vectors from RFC 8032 §7.1.
//
// They are reproduced here verbatim. TestEd25519RFC8032Vectors re-derives each
// signature with crypto/ed25519 before using it, so a transcription error in
// this table fails loudly rather than silently weakening every test below it.
var rfc8032Vectors = []struct {
	name    string
	secret  string // 32-byte seed
	public  string // A, compressed Edwards
	message string // M, raw (PureEdDSA)
	sig     string // R ‖ S, 64 bytes, S little-endian
}{
	{
		name:    "TEST_1_empty_message",
		secret:  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		public:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		message: "",
		sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
			"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	},
	{
		name:    "TEST_2_one_byte",
		secret:  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		public:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		message: "72",
		sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
			"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
	},
	{
		name:    "TEST_3_two_bytes",
		secret:  "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		public:  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		message: "af82",
		sig: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
			"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
	},
	{
		// 64-byte message: forces the challenge digest across a SHA-512 block
		// boundary, which a single-block-only implementation would get wrong.
		name:    "TEST_SHA_abc",
		secret:  "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
		public:  "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
			"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		sig: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589" +
			"09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestEd25519RFC8032Vectors checks the production challenge function and the
// production signature encoding directly against RFC 8032 §7.1.
//
// This is the test that would have caught a challenge that is not
// SHA-512(R ‖ A ‖ M) mod L, or an S encoded in the wrong byte order. Both are
// invisible to any test that only checks we agree with ourselves.
func TestEd25519RFC8032Vectors(t *testing.T) {
	group := curve.Ed25519{}

	for _, v := range rfc8032Vectors {
		t.Run(v.name, func(t *testing.T) {
			seed := mustHex(t, v.secret)
			pub := mustHex(t, v.public)
			msg := mustHex(t, v.message)
			sig := mustHex(t, v.sig)

			// 0. Pin the vector: crypto/ed25519 must reproduce it exactly.
			priv := ed25519.NewKeyFromSeed(seed)
			require.Equal(t, pub, []byte(priv.Public().(ed25519.PublicKey)),
				"transcribed public key is not the one RFC 8032 specifies")
			require.Equal(t, sig, ed25519.Sign(priv, msg),
				"transcribed signature is not the one RFC 8032 specifies")

			// 1. Decode R, A and S through the curve abstraction the protocol
			//    uses. Decoding also asserts R and A are in the prime-order
			//    subgroup and that S is canonical (S < L).
			var decoded Ed25519Signature
			require.NoError(t, decoded.UnmarshalBinary(group, sig),
				"our decoder must accept an RFC 8032 signature")

			A := group.NewPoint()
			require.NoError(t, A.UnmarshalBinary(pub))

			// 2. Recompute the challenge with the PRODUCTION function.
			c, err := ed25519Challenge(group, sig[:32], pub, msg)
			require.NoError(t, err)

			// 3. The RFC 8032 verification equation, in our own group
			//    arithmetic: [S]B = R + [k]A. Note this is checked as an exact
			//    group identity, not up to the cofactor, so it is the strict
			//    (cofactorless) form that crypto/ed25519 and ed25519-dalek's
			//    verify_strict both require.
			lhs := decoded.S.ActOnBase()
			rhs := c.Act(A).Add(decoded.R)
			assert.True(t, lhs.Equal(rhs),
				"challenge or encoding disagrees with RFC 8032: [S]B != R + [k]A")

			// 4. Re-encoding must reproduce the vector byte-for-byte. This is
			//    what pins S to little-endian: curve.Scalar.MarshalBinary is
			//    big-endian, so a missing reversal shows up here.
			reencoded, err := decoded.MarshalBinary()
			require.NoError(t, err)
			assert.Equal(t, sig, reencoded, "signature encoding is not RFC 8032")

			// 5. And the type's own Verify, which defers to crypto/ed25519.
			assert.True(t, decoded.Verify(A, msg))
		})
	}
}

// TestEd25519ChallengeRejectsWrongGroup makes sure the challenge cannot be
// silently computed over another group, which would produce 32 plausible bytes
// that no Ed25519 verifier accepts.
func TestEd25519ChallengeRejectsWrongGroup(t *testing.T) {
	for _, group := range []curve.Curve{curve.Secp256k1{}, curve.Ristretto255{}} {
		_, err := ed25519Challenge(group, make([]byte, 32), make([]byte, 32), []byte("m"))
		assert.Error(t, err, "challenge must refuse group %q", group.Name())
	}
}

// TestEd25519SignatureRejectsMalformed covers the decoder's negative cases.
func TestEd25519SignatureRejectsMalformed(t *testing.T) {
	group := curve.Ed25519{}
	valid := mustHex(t, rfc8032Vectors[1].sig)

	t.Run("wrong_length", func(t *testing.T) {
		var sig Ed25519Signature
		assert.Error(t, sig.UnmarshalBinary(group, valid[:63]))
		assert.Error(t, sig.UnmarshalBinary(group, append(append([]byte{}, valid...), 0)))
	})

	t.Run("non_canonical_S", func(t *testing.T) {
		// S = L is one past the largest canonical scalar, and is exactly the
		// malleability that RFC 8032 §5.1.7 and Solana's verifier reject.
		bad := append([]byte{}, valid...)
		copy(bad[32:], []byte{
			0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
			0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		})
		var sig Ed25519Signature
		assert.Error(t, sig.UnmarshalBinary(group, bad))
	})

	t.Run("torsion_R", func(t *testing.T) {
		// R replaced with the order-2 point (0, -1). It is a valid curve point,
		// so SetBytes alone would accept it.
		bad := append([]byte{}, valid...)
		copy(bad[:32], mustHex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
		var sig Ed25519Signature
		assert.Error(t, sig.UnmarshalBinary(group, bad),
			"R outside the prime-order subgroup must be rejected")
	})

	t.Run("nil_fields", func(t *testing.T) {
		_, err := Ed25519Signature{}.MarshalBinary()
		assert.Error(t, err)
		assert.False(t, Ed25519Signature{}.Verify(nil, nil))
	})
}
