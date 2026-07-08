// Package adapters - shared CSPRNG helper for LSS signature adapters.
package adapters

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// randIntn returns a cryptographically secure uniform random integer in the
// half-open range [0, n).
//
// Every Dilithium/ML-DSA secret polynomial, error polynomial, and masking
// polynomial (y) coefficient sampled anywhere in this package MUST go
// through this function — never through math/rand or math/rand/v2, which
// are not cryptographically secure PRNGs. A predictable or low-entropy mask
// y is exactly the ECDSA-style nonce-reuse footgun for lattice signatures:
// leaking (or being able to guess) even a few bits of y across signatures
// enables the same class of key-recovery attacks nonce reuse gives against
// Schnorr/ECDSA (Bleichenbacher-style lattice attacks on biased nonces).
//
// crypto/rand.Int already performs its own unbiased rejection sampling
// against crypto/rand.Reader internally, so no additional rejection loop
// is needed here — this is intentionally the one and only sampling path.
func randIntn(n int) int {
	if n <= 0 {
		panic(fmt.Sprintf("adapters: randIntn requires n > 0, got %d", n))
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// crypto/rand.Reader failing means the OS entropy source is broken.
		// There is no safe fallback when sampling secret/nonce material —
		// fail loudly rather than silently degrade to a weaker source.
		panic(fmt.Sprintf("adapters: crypto/rand.Reader failed: %v", err))
	}
	return int(v.Int64())
}
