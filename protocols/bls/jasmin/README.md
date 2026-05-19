# Threshold BLS Jasmin high-assurance track

This directory holds Jasmin sources for the BLS12-381 threshold
signature scheme (Lux profile), paired with the EasyCrypt theories
at `../proofs/easycrypt/`.

## Status — initial track

This is the **initial** high-assurance scaffolding. BLS-threshold
has the smallest Jasmin surface of the three classical threshold
protocols (FROST, CGGMP21, BLS):

| Layer | Operation | Status |
|---|---|---|
| Per-party sign | sigma_i = H(m)^{s_i} on G2 | Single G2 scalar mul |
| Aggregate | sigma = sum_i lambda_i * sigma_i | G2 weighted sum |
| Verify | e(sigma, g1) ?= e(H(m), pk) | Standard BLS pairing |

What we commit at this submission cycle:

1. Single-party BLS sign / verify Jazz signatures (stubs; libjade
   does NOT yet provide BLS12-381 Jasmin sources).
2. Threshold layer Jazz signatures (stubs; partial_sign and
   aggregate).
3. EasyCrypt theory shells at `../proofs/easycrypt/`.

## Layout

```
jasmin/
  lib/                       — shared helpers (transcript, params)
  single-party/              — single-party BLS sign / verify
    bls12_381_sign.jazz      — H(m)^{sk} on G2 (stub)
  threshold/                  — threshold layer
    partial_sign.jazz        — sigma_i = H(m)^{s_i} (stub)
    aggregate.jazz           — sum_i lambda_i * sigma_i (stub)
```

## Single-party BLS — circl integration

`luxfi/crypto/bls` wraps `cloudflare/circl/ecc/bls12381` which is
documented constant-time. Until libjade or formosa-crypto ships a
Jasmin port of BLS12-381, the Lux profile inherits CT from circl.

## Threshold layer — what each `.jazz` will do

| File | Algorithm | Mirrors Go reference |
|---|---|---|
| `partial_sign.jazz` | sigma_i = H(m)^{s_i} | `protocols/bls/bls.go:46 Sign` |
| `aggregate.jazz` | sigma = sum lambda_i * sigma_i | `protocols/bls/bls.go:65 AggregateSignatures` |

## Constant-time obligations

| Function | Secret input | CT obligation |
|---|---|---|
| `partial_sign` | share s_i | G2 scalar mul CT |
| `aggregate` | none | trivially CT |

## How to check

```bash
~/work/lux/threshold/scripts/check-high-assurance.sh
```

## Citations

- Almeida, Barbosa, Barthe, Blot, Grégoire, Laporte, Oliveira, Pacheco,
  Schwabe, Strub. *The last mile.* IEEE S&P 2020.
- Boldyreva, A. *Threshold signatures, multisignatures, and blind
  signatures based on the gap-Diffie-Hellman-group signature scheme.*
  PKC 2003.
- IETF CFRG. *draft-irtf-cfrg-bls-signature*. Wire-format reference.
