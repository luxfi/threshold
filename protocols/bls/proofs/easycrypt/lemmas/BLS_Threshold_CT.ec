(* -------------------------------------------------------------------- *)
(* BLS-Threshold -- Constant-time obligations                           *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL. Same BGL leakage model as FROST / CGGMP21 / Pulsar.   *)
(* -------------------------------------------------------------------- *)
(* BLS threshold's secret-touching surface is small:                    *)
(*   - partial_sign: secret = (share s_i).                              *)
(*       The only operation is sigma_i = H(m)^{s_i}, a G2 scalar mul.  *)
(*       CT depends on the underlying G2 scalar-mul implementation.    *)
(*   - aggregate:   no secret inputs => trivially CT.                   *)
(*                                                                      *)
(* CT inheritance: the Lux profile uses `cloudflare/circl` BLS12-381   *)
(* with its built-in CT G1/G2 scalar multiplication. Stated as the     *)
(* refinement obligation below.                                          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

type leakage_t.

type share_t.
type g2_t.
type message_t.
type sig_share_t.

module type CTPartialSign = {
  proc partial_sign(share : share_t, msg : message_t)
    : sig_share_t * leakage_t
}.

section PartialSignCT.

declare module PS <: CTPartialSign.

declare axiom partial_sign_constant_time
      (share1 share2 : share_t)
      (msg : message_t) :
    equiv [ PS.partial_sign ~ PS.partial_sign :
              ={msg}
              /\ share{1} = share1 /\ share{2} = share2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section PartialSignCT.

(* aggregate: no secret inputs; trivially CT. Stated for completeness. *)

(* -------------------------------------------------------------------- *)
(* End of BLS_Threshold_CT.ec                                            *)
(* -------------------------------------------------------------------- *)
