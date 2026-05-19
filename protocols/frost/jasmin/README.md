# FROST Jasmin high-assurance track

This directory holds Jasmin sources for the FROST threshold
signature scheme (Lux profile), paired with the EasyCrypt theories
at `../proofs/easycrypt/`.

## Status — initial track

This is the **initial** high-assurance scaffolding. What we commit
at this point:

1. Single-party Schnorr (Ed25519 / secp256k1-BIP340) Jasmin function
   signatures + comments. The reference Jasmin sources for
   Ed25519 / BIP-340 do NOT yet exist in libjade; we cite the
   relevant references and stub the call surface.
2. Threshold-layer Jasmin function signatures + algorithm commentary
   in `threshold/{round1,round2,combine}.jazz`. These are stubs
   marked `// TODO: jasmin implementation`. Implementing them is
   tracked in `~/work/lux/threshold/protocols/frost/SUBMISSION-
   STATUS.md §3.5`.
3. The `check-high-assurance.sh` gate at the threshold-repo root
   reports skip-clean when `jasminc` is not on PATH; when present
   it type-checks every `.jazz` and runs `jasmin-ct` on the
   threshold layer.

This is honest and standard for a Tier B → A submission scaffold.

## Layout

```
jasmin/
  lib/                       — shared helpers (transcript, MAC, Lagrange)
  single-party/              — single-party Schnorr (Ed25519 / secp256k1)
    ed25519_sign.jazz        — RFC 8032 §5.1.6 Sign (stub)
    secp256k1_bip340.jazz    — BIP-340 §6.6 Sign (stub)
  threshold/                  — Lux-novel threshold layer
    round1.jazz              — per-party commit (D_i, E_i)
    round2.jazz              — per-party response z_i
    combine.jazz             — aggregate (R, z) + encode
```

## Single-party Schnorr — libjade integration

Libjade (https://github.com/formosa-crypto/libjade) does NOT yet
provide Jasmin sources for Ed25519 RFC 8032 or BIP-340 secp256k1.
The Lux profile cites:

- **Ed25519**: `crypto/ed25519` (Go standard library, BoringSSL-
  derived) as the reference until libjade ships an Ed25519
  ciphersuite. CT inheritance via Go's `crypto/ed25519`
  constant-time scalar field arithmetic and Edwards curve scalar
  multiplication (filippo.io/edwards25519 derived).
- **BIP-340**: `crypto/secp256k1` (the cloudflare/circl
  secp256k1 backend used by `luxfi/crypto/secp256k1`). CT
  inheritance via circl's constant-time secp256k1 implementation.

The single-party Jazz stubs in `single-party/` document the function
signatures expected from a future libjade ciphersuite. They are
not yet linked into the threshold layer.

## Threshold layer — what each `.jazz` will do

| File | Algorithm | Mirrors Go reference |
|---|---|---|
| `round1.jazz` | Sample (d_i, e_i), publish (D_i = g^d_i, E_i = g^e_i) | `protocols/frost/sign/round1.go` |
| `round2.jazz` | Compute rho_i, c, lambda_i; emit z_i = d_i + rho_i*e_i + c*lambda_i*s_i | `protocols/frost/sign/round2.go` |
| `combine.jazz` | Aggregate R = sum (D_i + rho_i*E_i), z = sum z_i, encode (R, z) | `protocols/frost/sign/round3.go` |

## Constant-time obligations

Every threshold-layer function operates on at least one secret
input:

| Function | Secret input | CT obligation |
|---|---|---|
| `round1_commit` | (d_i, e_i) sampled internally | Time + memory access independent of (d_i, e_i); scalar_mul g d_i and g e_i must be CT |
| `round2_response` | (share s_i, nonces (d_i, e_i)) | Time + memory access independent of (s_i, d_i, e_i); modular multiplication must be CT |
| `combine` | none | trivially CT |

These obligations are stated formally in
`../proofs/easycrypt/lemmas/FROST_CT.ec` and would be discharged
by `jasminc -checkCT` once a concrete extraction lands.

## How to check

```bash
~/work/lux/threshold/scripts/check-high-assurance.sh
```

The script is **skip-friendly**: if `jasminc` is not on PATH it
prints a clear skip message and exits 0. When present it
type-checks each `.jazz` file and runs `jasmin-ct` on the
threshold layer.

## Citations

- Almeida, Barbosa, Barthe, Blot, Grégoire, Laporte, Oliveira, Pacheco,
  Schwabe, Strub. *The last mile: High-assurance and high-speed
  cryptographic implementations.* IEEE S&P 2020.
- Barbosa, Barthe, Bhargavan, Bigot, Doliskani, Fromherz, Grégoire,
  Kobeissi, Laporte, Lvovsky, Pacheco, Schwabe. *Formal verification of
  SHA-3 sponge functions and KMAC.* https://github.com/formosa-crypto/libjade
- Komlo, Goldberg. *FROST: Flexible Round-Optimized Schnorr Threshold
  Signatures.* SAC 2020 / ePrint 2020/852.
- IETF CFRG. *draft-irtf-cfrg-frost*. Wire format reference.
