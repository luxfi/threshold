# FROST EasyCrypt axiom inventory

> Honest enumeration of every `axiom` and `admit` in the FROST EC
> theories. Mirrors `~/work/lux/pulsar/AXIOM-INVENTORY.md` structure.

## Status

| Category | Count |
|---|---|
| Lean-bridged algebraic axioms (Lagrange / Shamir over F_r) | 4 |
| Ciphersuite byte-walk axioms (encoding equivalence) | 2 |
| Section-local declared axioms (FROST byte-walk) | 1 |
| Refinement-obligation axioms (Round-1/2/Combine vs honest spec) | 3 |
| CT obligations (concrete-impl-dependent declared axioms) | 2 |
| `admit`s in proof bodies | 1 |

The single `admit` (`frost_n4_pk_preservation_honest`) closes on a
one-line group-identity lemma (`derive_pk_group_identity`) that is
trivial in the abstract algebraic theory; it is left as a deferred
closure pending the FROST Lean module extension.

## Lean-bridged axioms (4)

These correspond 1:1 to proved Lean theorems. See
`~/work/lux/threshold/protocols/frost/proofs/lean-easycrypt-bridge.md`
for the full correspondence table.

| # | EC axiom | EC file:line | Lean theorem | Lean file |
|---|---|---|---|---|
| 1 | `scalar_add_zeroR` | `FROST_N1.ec:130` | `AddCommMonoid` instance | (Mathlib auto-derived) |
| 2 | `reconstruct_linear` | `FROST_N1.ec:135` | `combine_distributes_over_sum` | `Crypto/Threshold_Lagrange.lean:81` |
| 3 | `lagrange_inverse_eval` | `FROST_N1.ec:145` | `shamir_correct_at_target` | `Crypto/Pulsar/Shamir.lean:76` |
| 4 | `threshold_partial_response_identity` | `FROST_N1.ec:155` | `threshold_partial_response_identity` | `Crypto/Threshold_Lagrange.lean:135` |

## Ciphersuite byte-walk axioms (2)

Each pinned ciphersuite encodes (R, z) into the canonical signature
byte sequence per its IETF/BIP normative reference. These axioms
state that the threshold output bytes equal the single-party output
bytes under the pinned encoding.

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 5 | `ed25519_byte_equality` | `FROST_Ciphersuite_Ed25519.ec:80` | RFC 8032 §5.1.6 + Go `crypto/ed25519` |
| 6 | `secp_taproot_byte_equality` | `FROST_Ciphersuite_Secp256k1_Taproot.ec:103` | BIP-340 §6.6 + `crypto/secp256k1` |

## Section-local declared axioms (1)

The Combine-output byte-walk axiom mirrors Pulsar's
`combine_body_compute_sig_spec`: it states that the abstract Combine
module dispatches to single-party Schnorr Sign byte-for-byte under
an honest quorum. Discharged Jasmin-side once the threshold-layer
extraction is plugged in.

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 7 | `frost_combine_dispatches_to_schnorr` | `FROST_N1.ec:218` | `jasmin/threshold/combine.jazz` extraction |

## Refinement-obligation axioms (3)

Stated as deferred obligations in `FROST_N1_Refinement.ec` —
discharged once the Jasmin extraction lands. These axioms relate
the concrete `FROST_Ref` module's procedures to the abstract
honest-spec procedures.

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 8a | `round1_refinement_axiom` | `FROST_N1_Refinement.ec:84` | `jasmin/threshold/round1.jazz` extraction |
| 8b | `round2_refinement_axiom` | `FROST_N1_Refinement.ec:124` | `jasmin/threshold/round2.jazz` extraction |
| 8c | `combine_refinement_axiom` | `FROST_N1_Refinement.ec:160` | `jasmin/threshold/combine.jazz` extraction |

## CT obligations (2)

Concrete-implementation-dependent declared axioms. Each is a
property of the specific extracted code (not a theorem about
abstract modules), discharged by `jasminc -checkCT` constant-time
leakage analysis on the Jasmin sources or by empirical dudect on
the Go reference.

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 8 | `round1_constant_time` | `lemmas/FROST_CT.ec:67` | `jasmin/threshold/round1.jazz` |
| 9 | `round2_constant_time` | `lemmas/FROST_CT.ec:96` | `jasmin/threshold/round2.jazz` |

## `admit`s (1)

| # | Location | Closure |
|---|---|---|
| 10 | `FROST_N4.ec` `frost_n4_pk_preservation_honest` (final step) | `derive_pk_group_identity`: one-line algebraic lemma stating `group_pk_add P group_zero_pk = P` (group identity). Trivial in any abstract group theory; pending Lean module extension. |

## Closure roadmap

- **Axioms 1-4 (Lagrange)**: Closed in Lean. EC-side they remain as
  axioms; the bridge guard
  (`~/work/lux/threshold/scripts/check-high-assurance.sh`) enforces
  that each EC axiom carries a citation to its Lean theorem and
  that the Lean theorem exists at the named path.

- **Axioms 5-6 (ciphersuite byte-walks)**: Closed by inspection of
  the encode_signature_* operators against the IETF/BIP normative
  references. Mechanical closure would require a Jasmin extraction
  of the ciphersuite-specific encoding step.

- **Axiom 7 (FROST byte-walk)**: The protocol-level mirror of
  Pulsar's combine byte-walk. Closure requires the Jasmin extraction
  of `combine.jazz` to be linked against single-party Schnorr Sign.

- **Axioms 8-9 (CT)**: Discharged by `jasminc -checkCT` on the
  threshold-layer Jasmin sources.

- **Admit 10**: One-line algebraic lemma; closure is a single
  rewrite once the Lean side defines `group_pk_add` as the formal
  group operation.
