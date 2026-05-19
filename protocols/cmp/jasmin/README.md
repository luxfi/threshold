# CGGMP21 Jasmin high-assurance track

This directory holds Jasmin sources for the CGGMP21 threshold ECDSA
implementation (Lux profile), paired with the EasyCrypt theories
at `../proofs/easycrypt/`.

## Status — initial track

This is the **initial** high-assurance scaffolding. CGGMP21 is
substantially more demanding than FROST or BLS because it requires:

1. Paillier encryption with biprime modulus (2048-bit) and
   constant-time CRT-based decryption.
2. Seventeen distinct zero-knowledge subprotocols (range proofs,
   knowledge proofs, equality proofs, factoring proofs).
3. MtA (multiplicative-to-additive) conversion with two-sided ZK
   wrapping.

Libjade does **not** provide Jasmin sources for any of the above.
The Lux profile's Jasmin scaffold here is therefore stub-level
for the Paillier path and stub-level for the threshold round
machinery.

## Layout

```
jasmin/
  lib/                       — shared helpers (transcript, Paillier params)
  single-party/              — single-party RFC 6979 secp256k1 ECDSA
    secp256k1_ecdsa.jazz     — RFC 6979 / SEC1 sign (stub)
  presign/                    — CGGMP21 presign Round 1, 2, 3
    round1.jazz              — sample (k_i, gamma_i), Paillier-encrypt
    round2.jazz              — MtA exchange + ZK responses
    round3.jazz              — Gamma aggregation, R derivation
  threshold/                  — sign online phase
    sign_online.jazz         — s_i computation
```

## Single-party ECDSA — circl integration

The Lux profile uses `cloudflare/circl` secp256k1 (re-exported via
`luxfi/crypto/secp256k1`) which is documented constant-time by
upstream. Until libjade ships a Jasmin port of secp256k1 ECDSA,
the Lux profile inherits CT from circl.

## Paillier — open problem

CCS '21 §6.1 mandates biprime moduli (N = pq with p, q safe primes).
Generating safe primes in constant time is itself non-trivial; the
Lux profile uses `pkg/paillier` (based on `cronokirby/saferith`)
which provides CT modular arithmetic. A Jasmin port of safe-prime
generation does not exist upstream and is not planned for this
submission cycle.

## Threshold layer — what each `.jazz` will do

| File | Algorithm | Mirrors Go reference |
|---|---|---|
| `presign/round1.jazz` | Sample (k_i, gamma_i), publish Paillier-enc commitments | `protocols/cmp/presign/round1.go` |
| `presign/round2.jazz` | MtA exchange: Paillier-mul-then-blind, ZK responses | `protocols/cmp/presign/round2.go` |
| `presign/round3.jazz` | Compute Gamma = sum Gamma_j, R = Gamma^{k^{-1}} | `protocols/cmp/presign/round3.go` |
| `threshold/sign_online.jazz` | s_i = k_i_inv * m + r * chi_i (mod n) | `protocols/cmp/sign/sign.go` |

## Constant-time obligations

| Function | Secret input | CT obligation |
|---|---|---|
| `presign_round1` | (k_i, gamma_i, paillier_sk) | Sampling + Paillier-enc CT; ZK prover CT |
| `presign_round2` | Paillier MtA-dec, beta_j | Paillier dec CT (CRT-based mod exp) |
| `presign_round3` | k_i, gamma_i | Modular multiplication CT |
| `sign_online` | k_i_inv_share, chi_share, share | Scalar multiplication + addition CT |

These obligations are stated formally in
`../proofs/easycrypt/lemmas/CGGMP21_CT.ec`.

## How to check

```bash
~/work/lux/threshold/scripts/check-high-assurance.sh
```

The script is skip-friendly when `jasminc` is not on PATH.

## Citations

- Almeida, Barbosa, Barthe, Blot, Grégoire, Laporte, Oliveira, Pacheco,
  Schwabe, Strub. *The last mile: High-assurance and high-speed
  cryptographic implementations.* IEEE S&P 2020.
- Canetti, Gennaro, Goldfeder, Makriyannis, Peled.
  *UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable
  Aborts.* CCS 2021 / ePrint 2021/060.
- Paillier, P. *Public-Key Cryptosystems Based on Composite Degree
  Residuosity Classes.* Eurocrypt 1999.
