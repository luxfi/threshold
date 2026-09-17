// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package tfhe is threshold fully-homomorphic encryption: a committee of n
// members at threshold t decrypts without any member holding the key.
//
//	pub, shares := Keygen(params, t, n, seed)
//	ct          := Encrypt(params, pub, v, fhe.FheUint8)
//	d           := member.Decrypt(ct, prng)
//	bits        := Decrypt(ct, []Decryption{d, ...}, params, t)
//
// Key generation is in keygen.go, the decryption kernel in partial.go, and the
// committee layer a networked caller needs in committee.go and decrypt.go.
// Custody and correctness are proved in lux/proofs/fhe/threshold-custody.tex.
package tfhe
