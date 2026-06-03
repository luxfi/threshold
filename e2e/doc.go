// SPDX-License-Identifier: BSD-3-Clause

// Package e2e is the production-validation harness for the PQ threshold
// custody flow against the live testnet luxd cluster.
//
// What this package does
//
//   - Drives the in-process pulsar / ringtail / magnetar dispatchers from
//     pkg/thresholdd over the JSON-RPC HTTP surface. Same code path
//     that mpcd hosts in production.
//
//   - Times every step with wall-clock deltas from time.Now().
//
//   - Strips the PULS / MAGS wire envelopes to recover the FIPS 204 /
//     FIPS 205 payload bytes, and feeds them to
//     cloudflare/circl/sign/{mldsa/mldsa65, slhdsa} verifiers with no
//     pulsar / magnetar code path on the verifier side.
//
//   - Submits a real C-Chain native-token transfer against the live
//     Lux testnet luxd RPC and waits for inclusion in a block. This
//     is the chain-liveness gate that proves the production cluster
//     accepts and finalises transactions while the PQ harness runs.
//
//   - Records every measurement (keygen_ns, sign_ns, sig_bytes,
//     external_verify_ok, block_height, tx_hash) and prints a report
//     readable by PRODUCTION-VALIDATION-2026-05-31.md.
//
// What it does NOT do
//
//   - Does NOT exercise the on-chain ML-DSA / SLH-DSA precompiles
//     (slots 0x012202 / 0x012203). Those precompiles call
//     VerifySignatureCtx with precompileCtx = "lux-evm-precompile-{mldsa,
//     slhdsa}-v1"; the dispatcher's Sign API does not bind that ctx,
//     so a dispatcher-produced signature deliberately would NOT verify
//     under the precompile. That is a separate ctx-binding test (the
//     dispatcher would need a Sign_Ctx method that takes the EVM
//     precompile ctx — out of scope for this validation pass).
//
//   - Does NOT exercise the ringtail-on-chain path (no FIPS standard for
//     R-LWE; ringtail's external verifier is the Ringtail kernel
//     VerifyBytes invoked outside any threshold/luxd code path).
//
// Run
//
//	go test ./e2e -run TestProductionValidation_All -v -count=1 -timeout=10m
//
// The harness is hard-coded against the public Lux testnet
// LoadBalancer (134.199.187.16:9640). Run from a host with network
// reach to that IP.
package e2e
