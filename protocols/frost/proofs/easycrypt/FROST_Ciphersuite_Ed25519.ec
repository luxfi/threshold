(* -------------------------------------------------------------------- *)
(* FROST -- Ciphersuite layer: FROST(Ed25519, SHA-512)                  *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* Reference: IETF `draft-irtf-cfrg-frost` Ciphersuite                  *)
(* "FROST(Ed25519, SHA-512)" + Lux LP-4711.                             *)
(*                                                                      *)
(* Pinned parameters                                                    *)
(* -----------------                                                    *)
(*   Group           = edwards25519 (RFC 8032 §5.1).                    *)
(*   Scalar field    = Z_L where L = 2^252 + ...                        *)
(*   Cofactor h      = 8 (handled by clamping per RFC 8032).            *)
(*   Hash            = SHA-512.                                         *)
(*   Encoding        = RFC 8032 §5.1.6 signature encoding (R || s,      *)
(*                     64 bytes total).                                 *)
(*   Single-party    = `crypto/ed25519` (Go standard library) /         *)
(*   verifier          libsodium / NaCl. RFC 8032 §5.1.7 verify.        *)
(*                                                                      *)
(* This file pins the Ed25519 instantiation of the abstract operators   *)
(* in `FROST_N1.ec`. The byte-equality claim against `crypto/ed25519`   *)
(* lives here.                                                          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.
require import FROST_N1.

(* -------------------------------------------------------------------- *)
(* Pinned scalar field: Z_L (edwards25519 group order).                 *)
(* -------------------------------------------------------------------- *)

(* L = 2^252 + 27742317777372353535851937790883648493.                    *)
(* Stated as an abstract constant here; the concrete decimal is in      *)
(* `~/work/lux/threshold/protocols/frost/PARAMS.md`.                    *)
op ed25519_L : int.
axiom ed25519_L_value : ed25519_L = 7237005577332262213973186563042994240857116359379907606001950938285454250989.

(* -------------------------------------------------------------------- *)
(* Pinned hash: SHA-512.                                                 *)
(* -------------------------------------------------------------------- *)

op sha512 : byte_seq -> byte_seq.

(* Binding factor: H1 in Komlo-Goldberg §6.1 = SHA-512(domain || ...).  *)
op h1_ed25519 : byte_seq -> scalar_t.
axiom h1_ed25519_def :
  forall (b : byte_seq),
    h1_ed25519 b = h_binding (sha512 (witness ++ b)).  (* "FROST-ED25519-SHA512-v1" || b *)

(* Challenge: H2 = SHA-512("FROST-ED25519-SHA512-v1" || R || PK || m). *)
op h2_ed25519 : byte_seq -> scalar_t.
axiom h2_ed25519_def :
  forall (b : byte_seq),
    h2_ed25519 b = h_challenge (sha512 (witness ++ b)).

(* -------------------------------------------------------------------- *)
(* Pinned signature encoding: RFC 8032 §5.1.6.                          *)
(* -------------------------------------------------------------------- *)
(* Sig = ENC(R) || ENC(s), 64 bytes total                                *)
(*   ENC(R)  = compressed Ed25519 point, 32 bytes                       *)
(*   ENC(s)  = little-endian scalar mod L, 32 bytes                     *)
(* -------------------------------------------------------------------- *)

op encode_point_ed25519 : point_t -> byte_seq.
op encode_scalar_ed25519 : scalar_t -> byte_seq.

op encode_signature_ed25519 (R : point_t) (s : scalar_t) : signature_t =
  witness.  (* Concrete byte sequence encode_point_ed25519 R ++ encode_scalar_ed25519 s; abstract here. *)

(* -------------------------------------------------------------------- *)
(* Byte-equality claim vs `crypto/ed25519`                              *)
(* -------------------------------------------------------------------- *)
(* Single-party Ed25519 Sign per RFC 8032 §5.1.6 / Go crypto/ed25519     *)
(* produces the same byte sequence as FROST Combine over an honest      *)
(* quorum on the Lagrange-reconstructed secret. This is the deferred    *)
(* byte-walk obligation; it composes the protocol-level                  *)
(* `frost_combine_dispatches_to_schnorr` axiom from `FROST_N1.ec` with  *)
(* the Ed25519 encoding above.                                          *)
(* -------------------------------------------------------------------- *)

axiom ed25519_byte_equality :
  forall (s : share_t) (msg : message_t) (R : point_t) (z : scalar_t),
    encode_signature_ed25519 R z =
    encode_signature R z.

(* -------------------------------------------------------------------- *)
(* End of FROST_Ciphersuite_Ed25519.ec                                  *)
(* -------------------------------------------------------------------- *)
