# Corona — threshold Ring-LWE

Corona is Lux's Ring-LWE threshold signature, the intra-lattice
diversity layer alongside Pulsar's Module-LWE construction. Same
2-round Pedersen-DKG + threshold-sign skeleton, but everything lives
in `R_q` rather than `R_q^k`, so the per-party state is a single ring
polynomial instead of a polyvecl.

## Construction (one paragraph)

Per `corona/sign/sign.go`: each party `i` samples a fresh mask `y_i ∈
R_q`, broadcasts a Round-1 commit `D_i = cSHAKE(w_i, "CORONA-SIGN-R1")`
together with sender-MACs. After collecting peer commits, each party
derives the Fiat-Shamir challenge `c̃ = SHAKE(μ ‖ Σ w_j)`, expands `c
= SampleInBall(c̃) ∈ R_q`, computes its Lagrange coefficient `λ_i^T ∈
Z_q` over the active quorum, and emits the Round-2 response `z_i =
y_i + c · λ_i · s_i` along with the per-party blinding contribution
`r_i = c · λ_i · u_i`. Combine aggregates `z = Σ z_j`, `c·s_2 = Σ
r_j`, applies the Ring-LWE rejection check (norms within Corona's
`γ_1 - β` / `γ_2 - β` bounds), and emits the wire signature `σ = (C,
Z, Δ)` — a 33,052-byte triple of ring polynomials.

## Key claims

| Claim | Status |
|---|---|
| Threshold reconstructs the secret | `corona_threshold_reconstructs` in `proofs/lean/Crypto/Corona.lean` (re-uses `Crypto.Threshold.Lagrange.threshold_reconstructs_secret`) |
| Combine linearity (Lagrange) | `corona_combine_linear` in `proofs/lean/Crypto/Corona.lean` |
| EUF-CMA under Ring-LWE | `corona_ring_lwe_euf_cma` (axiomatic, cites Boschini–Kaviani–Lai–Malavolta–Takahashi–Tibouchi IACR 2024/1113 §5) |
| Threshold robustness | `corona_robustness` in `proofs/lean/Crypto/Corona.lean` |
| Cross-domain isolation from Pulsar | WEAK per BLOCKERS.md: MLWE ⊃ RLWE, so "intra-lattice diversity" is the right framing — not "family-disjoint" |

## Artifacts

| Where | What |
|---|---|
| `~/work/lux/corona/` | Library (production Go implementation) |
| `~/work/lux/corona/sign/sign.go` | 2-round threshold + Verify |
| `~/work/lux/corona/dkg/`, `dkg2/` | DKG protocols |
| `~/work/lux/precompile/corona/` | EVM precompile at 0x012206 |
| `~/work/lux/proofs/lean/Crypto/Corona.lean` | Lean structural proof |
| `~/work/lux/papers/lux-corona-pq/lux-ringtail-pq.tex` | Paper (filename retains pre-rename `ringtail` qualifier; content describes Corona) |
| `~/work/lux/threshold/protocols/corona/` | Threshold-protocol library entry point |

## Parameter set

```
N (ring dimension)     256
q (modulus)            2^32
σ (Gaussian noise)     13744
n_LWE                  630   (lattice dimension)
γ_1                    Corona-specific (see corona/primitives/)
γ_2                    Corona-specific
β                      Corona-specific
Security target        128-bit classical / 130-bit quantum (BDGL sieving)
```

The 130-bit quantum target exceeds the NIST PQ Category 1 bar
(2^128 / 2^64-quantum) but does not reach Category 3 (2^192). Use
Pulsar at L65 (192-bit) for higher security tiers; Corona is the
defense-in-depth lattice-diversity layer, not a security-tier upgrade.

## Open items

- Cross-domain isolation claim from Pulsar: weak (BLOCKERS.md). Both
  primitives rest on lattice-family hardness — a structural break
  against MLWE / RLWE compromises both. Real cross-family DiD comes
  from Comet (hash) in the Magnetar profile.
- No EasyCrypt / Jasmin high-assurance track for Corona yet (Pulsar
  has both at theory-shell level).
- Paper file at `papers/lux-corona-pq/lux-ringtail-pq.tex` retains
  the old `ringtail` filename; rename to `lux-corona-pq.tex` is a
  pending tidy-up.

## See also

- [README.md](README.md) — comparative index for the 3 PQ threshold tiers.
- [pulsar.md](pulsar.md) — Module-LWE sibling.
- [comet.md](comet.md) — hash-based tier (cross-family diversity).
