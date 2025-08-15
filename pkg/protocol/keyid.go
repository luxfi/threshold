package protocol

import (
	"sort"

	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// KeyID represents a stable, phase-independent identifier for a key generation
// context. This is used for cross-phase cryptographic commitments and verification.
//
// Unlike sessionID which changes per phase for anti-replay, KeyID remains constant
// across all phases (keygen, presign, sign) to ensure cryptographic bindings
// remain valid.
type KeyID struct {
	// ProtocolID identifies the protocol (e.g., "cmp/keygen", "frost/keygen")
	ProtocolID string
	// Group is the elliptic curve group being used
	Group curve.Curve
	// PublicKey is the shared public key (if available)
	PublicKey curve.Point
	// PartyIDs is the canonical ordered list of all parties
	PartyIDs []party.ID
	// Threshold is the threshold parameter
	Threshold int
	// Generation is an optional generation counter for key refresh
	Generation uint32
}

// NewKeyID creates a new KeyID for a key generation context.
// The partyIDs will be canonically sorted to ensure consistency.
func NewKeyID(protocolID string, group curve.Curve, publicKey curve.Point, partyIDs []party.ID, threshold int, generation uint32) *KeyID {
	// Create a copy and sort party IDs to ensure canonical ordering
	sortedParties := make([]party.ID, len(partyIDs))
	copy(sortedParties, partyIDs)
	sort.Slice(sortedParties, func(i, j int) bool {
		return sortedParties[i] < sortedParties[j]
	})

	return &KeyID{
		ProtocolID: protocolID,
		Group:      group,
		PublicKey:  publicKey,
		PartyIDs:   sortedParties,
		Threshold:  threshold,
		Generation: generation,
	}
}

// Hash returns a cryptographic hash of the KeyID that can be used
// for commitments and verification across phases.
func (k *KeyID) Hash() *hash.Hash {
	h := hash.New()

	// Include protocol ID
	_ = h.WriteAny(&hash.BytesWithDomain{
		TheDomain: "KeyID Protocol",
		Bytes:     []byte(k.ProtocolID),
	})

	// Include group name
	if k.Group != nil {
		_ = h.WriteAny(&hash.BytesWithDomain{
			TheDomain: "KeyID Group",
			Bytes:     []byte(k.Group.Name()),
		})
	}

	// Include public key if available
	// Note: We don't include public key for keygen since it's not known yet
	// This field is mainly for future phases after keygen
	if k.PublicKey != nil && !k.PublicKey.IsIdentity() {
		_ = h.WriteAny(k.PublicKey)
	}

	// Include canonical party IDs
	partySlice := party.NewIDSlice(k.PartyIDs)
	_ = h.WriteAny(partySlice)

	// Include threshold
	_ = h.WriteAny(types.ThresholdWrapper(k.Threshold))

	// Include generation if non-zero
	if k.Generation > 0 {
		genBytes := make([]byte, 4)
		genBytes[0] = byte(k.Generation >> 24)
		genBytes[1] = byte(k.Generation >> 16)
		genBytes[2] = byte(k.Generation >> 8)
		genBytes[3] = byte(k.Generation)
		_ = h.WriteAny(&hash.BytesWithDomain{
			TheDomain: "KeyID Generation",
			Bytes:     genBytes,
		})
	}

	return h
}

// HashForParty returns a hash initialized with the KeyID and a specific party ID.
// This is useful for party-specific commitments that need to be stable across phases.
func (k *KeyID) HashForParty(id party.ID) *hash.Hash {
	h := k.Hash()
	if id != "" {
		_ = h.WriteAny(id)
	}
	return h
}

// Bytes returns the hash sum of the KeyID as a byte slice.
func (k *KeyID) Bytes() []byte {
	return k.Hash().Sum()
}
