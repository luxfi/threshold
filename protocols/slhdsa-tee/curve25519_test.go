// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import "golang.org/x/crypto/curve25519"

// curve25519BasepointMul is a test-only helper that returns the
// public half of a clamped X25519 private scalar. Lives in a
// _test.go file so the production package surface does not export it.
func curve25519BasepointMul(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}
