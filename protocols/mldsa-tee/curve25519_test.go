// SPDX-License-Identifier: BSD-3-Clause

package mldsatee

import "golang.org/x/crypto/curve25519"

// curve25519BasepointMul is a test-only helper.
func curve25519BasepointMul(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}
