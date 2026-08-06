package frost

import (
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost/keygen"
	"github.com/luxfi/threshold/protocols/frost/sign"
)

type (
	Config           = keygen.Config
	TaprootConfig    = keygen.TaprootConfig
	Signature        = sign.Signature
	SR25519Signature = sign.SR25519Signature
	Ed25519Signature = sign.Ed25519Signature
)

// EmptyConfig creates an empty Config with a specific group.
//
// This needs to be called before unmarshalling, instead of just using new(Result).
// This is to allow points and scalars to be correctly unmarshalled.
func EmptyConfig(group curve.Curve) *Config {
	return &keygen.Config{
		PrivateShare:       group.NewScalar(),
		PublicKey:          group.NewPoint(),
		VerificationShares: party.EmptyPointMap(group),
	}
}

// Keygen initiates the Frost key generation protocol.
//
// This protocol establishes a new threshold signature key among a set of participants.
// Later, a subset of these participants can create signatures for this public key,
// using the private shares created in this protocol.
//
// participants is a complete set of parties that will hold a share of the secret key.
// Future signers must come from this set.
//
// threshold is the number of participants that can be corrupted without breaking
// the security of the protocol. In the future, threshold + 1 participants will need
// to cooperate to produce signatures.
//
// selfID is the identifier for the local party calling this function.
//
// This protocol corresponds to Figure 1 of the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return keygen.StartKeygenCommon(false, group, participants, threshold, selfID, nil, nil, nil)
}

// KeygenTaproot is like Keygen, but will make Taproot / BIP-340 compatible keys.
//
// This will also return TaprootResult instead of Result, at the end of the protocol.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
func KeygenTaproot(selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return keygen.StartKeygenCommon(true, curve.Secp256k1{}, participants, threshold, selfID, nil, nil, nil)
}

// Refresh
func Refresh(config *Config, participants []party.ID) protocol.StartFunc {
	return keygen.StartKeygenCommon(false, config.Curve(), participants, config.Threshold, config.ID, config.PrivateShare, config.PublicKey, config.VerificationShares.Points)
}

// RefreshTaproot is like Refresh, but will make Taproot / BIP-340 compatible keys.
//
// This will also return TaprootResult instead of Result, at the end of the protocol.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
func RefreshTaproot(config *TaprootConfig, participants []party.ID) protocol.StartFunc {
	publicKey, err := curve.Secp256k1{}.LiftX(config.PublicKey)
	if err != nil {
		return func([]byte) (round.Session, error) {
			return nil, err
		}
	}
	verificationShares := make(map[party.ID]curve.Point, len(config.VerificationShares))
	for k, v := range config.VerificationShares {
		verificationShares[k] = v
	}
	return keygen.StartKeygenCommon(true, curve.Secp256k1{}, participants, config.Threshold, config.ID, config.PrivateShare, publicKey, verificationShares)
}

// KeygenSR25519 initiates the Frost key generation protocol for sr25519 keys.
//
// This generates key shares over the Ristretto255 group, compatible with the
// sr25519 (Schnorrkel) signature scheme used by Substrate/Polkadot.
func KeygenSR25519(selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return keygen.StartKeygenCommon(false, curve.Ristretto255{}, participants, threshold, selfID, nil, nil, nil)
}

// RefreshSR25519 refreshes sr25519 key shares without changing the public key.
func RefreshSR25519(config *Config, participants []party.ID) protocol.StartFunc {
	return keygen.StartKeygenCommon(false, config.Curve(), participants, config.Threshold, config.ID, config.PrivateShare, config.PublicKey, config.VerificationShares.Points)
}

// KeygenEd25519 initiates the Frost key generation protocol for Ed25519 keys.
//
// This generates key shares over edwards25519. The resulting 32-byte public key
// is a plain RFC 8032 public key: base58-encoded it is a Solana address, and it
// is the key a TON wallet contract stores. Nothing distinguishes it on chain
// from a single-signer key, because nothing about it is different — only the way
// the corresponding secret is held.
//
// Signatures are produced by SignEd25519. There is no separate refresh entry
// point: Refresh already takes the group from the config, so it refreshes an
// Ed25519 config as it stands.
func KeygenEd25519(selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return keygen.StartKeygenCommon(false, curve.Ed25519{}, participants, threshold, selfID, nil, nil, nil)
}

// Sign initiates the protocol for producing a threshold signature, with Frost.
//
// result is the result of the key generation phase, for this participant.
//
// signers is the list of all participants generating a signature together, including
// this participant.
//
// messageHash is the hash of the message a signature should be generated for.
//
// This protocol merges Figures 2 and 3 from the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// We merge the pre-processing and signing protocols into a single signing protocol
// which doesn't require any pre-processing.
//
// Another major difference is that there's no central "Signing Authority".
// Instead, each participant independently verifies and broadcasts items as necessary.
//
// Differences stemming from this change are commented throughout the protocol.
func Sign(config *Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return sign.StartSignCommon(false, config, signers, messageHash)
}

// SignTaproot is like Sign, but will generate a Taproot / BIP-340 compatible signature.
//
// This needs to result of a Taproot compatible key generation phase, naturally.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
func SignTaproot(config *TaprootConfig, signers []party.ID, messageHash []byte) protocol.StartFunc {
	publicKey, err := curve.Secp256k1{}.LiftX(config.PublicKey)
	if err != nil {
		return func([]byte) (round.Session, error) {
			return nil, err
		}
	}
	genericVerificationShares := make(map[party.ID]curve.Point)
	for k, v := range config.VerificationShares {
		genericVerificationShares[k] = v
	}
	normalResult := &keygen.Config{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       config.PrivateShare,
		PublicKey:          publicKey,
		VerificationShares: party.NewPointMap(genericVerificationShares),
	}
	return sign.StartSignCommon(true, normalResult, signers, messageHash)
}

// SignSR25519 initiates the protocol for producing an sr25519 (Schnorrkel) compatible
// threshold signature.
//
// config must come from a KeygenSR25519 key generation (Ristretto255 group).
//
// signingContext is the application-level context label. For Substrate this is "substrate".
// If nil, defaults to "substrate".
//
// message is the raw message bytes (NOT pre-hashed). The Merlin transcript handles
// domain separation internally.
func SignSR25519(config *Config, signers []party.ID, signingContext []byte, message []byte) protocol.StartFunc {
	if signingContext == nil {
		signingContext = []byte("substrate")
	}
	return sign.StartSignSR25519Common(false, true, signingContext, config, signers, message)
}

// SignEd25519 initiates the protocol for producing an RFC 8032 (PureEdDSA)
// threshold signature.
//
// config must come from KeygenEd25519 (or a Refresh of one), i.e. the edwards25519
// group.
//
// message is the raw message bytes. PureEdDSA signs M itself, hashing it inside
// the challenge, so callers must NOT pre-hash: for Solana pass the serialized
// transaction message, and for TON pass the 32 bytes of the cell hash to be
// signed. Pre-hashing here would sign the wrong thing and the chain would reject
// it — or worse, accept a signature over a digest of a digest.
//
// The result is an Ed25519Signature, whose 64-byte encoding crypto/ed25519
// verifies against the 32-byte public key from keygen.
func SignEd25519(config *Config, signers []party.ID, message []byte) protocol.StartFunc {
	return sign.StartSignEd25519Common(config, signers, message)
}
