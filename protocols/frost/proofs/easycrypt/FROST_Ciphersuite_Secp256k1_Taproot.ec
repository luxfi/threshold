(* -------------------------------------------------------------------- *)
(* FROST -- Ciphersuite layer: FROST(secp256k1, SHA-256) + BIP-340      *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* Reference: IETF `draft-irtf-cfrg-frost` Ciphersuite                  *)
(* "FROST(secp256k1, SHA-256)" + BIP-340 (Bitcoin Taproot) +            *)
(* Lux LP-4712.                                                         *)
(*                                                                      *)
(* Pinned parameters                                                    *)
(* -----------------                                                    *)
(*   Group           = secp256k1 (Standards for Efficient Cryptography).*)
(*   Scalar field    = Z_n where n = 2^256 - 432420386565659656852420   *)
(*                     866394968145599 (secp256k1 group order).         *)
(*   Cofactor h      = 1.                                               *)
(*   Hash            = SHA-256 (tagged per BIP-340).                    *)
(*   Encoding        = BIP-340 §6.6 signature encoding (r || s,         *)
(*                     64 bytes total, x-only public key).              *)
(*   Single-party    = BIP-340 reference implementation /               *)
(*   verifier          `crypto/secp256k1` Schnorr.                      *)
(*                                                                      *)
(* This file pins the secp256k1-Taproot instantiation of the abstract  *)
(* operators in `FROST_N1.ec`. The byte-equality claim against         *)
(* BIP-340 Schnorr lives here.                                          *)
(*                                                                      *)
(* Taproot-specific delta vs vanilla FROST(secp256k1):                  *)
(*   - X-only public key (32 bytes, BIP-340 §2).                        *)
(*   - Even-Y normalization on group_pk and aggregated R commitments.  *)
(*   - Tagged-SHA256 challenge: H("BIP0340/challenge", r||PK||m).      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.
require import FROST_N1.

(* -------------------------------------------------------------------- *)
(* Pinned scalar field: Z_n (secp256k1 group order).                    *)
(* -------------------------------------------------------------------- *)

(* n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 *)
op secp256k1_n : int.
axiom secp256k1_n_value :
  secp256k1_n = 115792089237316195423570985008687907852837564279074904382605163141518161494337.

(* -------------------------------------------------------------------- *)
(* Pinned hash: SHA-256 (tagged per BIP-340).                           *)
(* -------------------------------------------------------------------- *)

op sha256 : byte_seq -> byte_seq.

op tagged_sha256 (tag : byte_seq) (msg : byte_seq) : byte_seq =
  sha256 (sha256 tag ++ sha256 tag ++ msg).

(* BIP-340 tag bytes (UTF-8 encoded; abstract here).                    *)
op bip340_challenge_tag : byte_seq.
op bip340_aux_tag : byte_seq.
op bip340_nonce_tag : byte_seq.

(* Binding factor for FROST(secp256k1, SHA-256): from Komlo-Goldberg    *)
(* §6.2 with the IETF draft tagging.                                    *)
op h1_secp_taproot : byte_seq -> scalar_t.

(* Tagged challenge per BIP-340 §3.2: c = H("BIP0340/challenge",         *)
(* x(R) || x(PK) || m).                                                  *)
op h2_secp_taproot : byte_seq -> scalar_t.

axiom h2_secp_taproot_def :
  forall (b : byte_seq),
    h2_secp_taproot b = h_challenge (tagged_sha256 bip340_challenge_tag b).

(* -------------------------------------------------------------------- *)
(* Even-Y normalization (BIP-340 §2).                                   *)
(* -------------------------------------------------------------------- *)
(* For Taproot: if a point's Y-coordinate is odd, negate the point and  *)
(* (for the signer) negate the corresponding secret. This ensures the   *)
(* x-only encoding is unambiguous.                                       *)

op is_even_y : point_t -> bool.

op normalize_to_even_y (P : point_t) : point_t =
  if is_even_y P then P else witness.  (* P -> -P; abstract here. *)

op normalize_secret_for_even_y (sk : scalar_t) (PK : point_t) : scalar_t =
  if is_even_y PK then sk else scalar_neg sk.

(* -------------------------------------------------------------------- *)
(* Pinned signature encoding: BIP-340 §6.6.                             *)
(* -------------------------------------------------------------------- *)
(* Sig = x(R) || s, 64 bytes total                                       *)
(*   x(R) = x-coordinate of R, 32 bytes big-endian                      *)
(*   s    = scalar response, 32 bytes big-endian                         *)
(* -------------------------------------------------------------------- *)

op encode_xpoint_secp : point_t -> byte_seq.
op encode_scalar_secp : scalar_t -> byte_seq.

op encode_signature_secp_taproot (R : point_t) (s : scalar_t) : signature_t =
  witness.  (* Concrete byte sequence encode_xpoint_secp R ++ encode_scalar_secp s. *)

(* -------------------------------------------------------------------- *)
(* Byte-equality claim vs BIP-340 single-party Schnorr                  *)
(* -------------------------------------------------------------------- *)

axiom secp_taproot_byte_equality :
  forall (s : share_t) (msg : message_t) (R : point_t) (z : scalar_t),
    encode_signature_secp_taproot
      (normalize_to_even_y R)
      (if is_even_y R then z else scalar_neg z) =
    encode_signature R z.

(* -------------------------------------------------------------------- *)
(* End of FROST_Ciphersuite_Secp256k1_Taproot.ec                        *)
(* -------------------------------------------------------------------- *)
