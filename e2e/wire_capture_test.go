// SPDX-License-Identifier: BSD-3-Clause
package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"testing"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	circlslhdsa "github.com/cloudflare/circl/sign/slhdsa"
	coronaThreshold "github.com/luxfi/corona/threshold"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

// TestProductionValidation_WireCapture is the byte-identity capture
// test. It produces one fresh keygen + signature for each scheme,
// then prints a Markdown-table-friendly summary of:
//
//   - the SHA-256 of the wire group public key bytes
//   - the SHA-256 of the wire signature bytes
//   - the SHA-256 of the FIPS-stripped payload bytes
//   - the exact call signature used by the external verifier
//
// The committed PRODUCTION-VALIDATION-2026-05-31.md report pulls
// these hashes verbatim so the byte-identity claim is reproducible
// at the SHA-256 hash level. The test also records:
//
//   - circl mldsa65.Verify(&pk, msg, nil, fipsSig) == true
//   - circl slhdsa.Verify(&pk, NewMessage(msg), fipsSig, nil) == true
//   - corona.VerifyBytes(gkBytes, string(msg), sigBytes) == true
func TestProductionValidation_WireCapture(t *testing.T) {
	srv, err := thresholdd.NewServer()
	if err != nil {
		t.Fatalf("thresholdd.NewServer: %v", err)
	}
	hs := httptest.NewServer(srv)
	defer hs.Close()

	msg := []byte("WIRE-CAPTURE 2026-05-31 byte-identity reproducer")
	t.Logf("CAPTURE-MSG-SHA256 : %s", hexShort(sha256.Sum256(msg)))

	// --- pulsar ---
	{
		kg, err := rpcCall(hs.URL, "pulsar.keygen", map[string]any{"threshold": 3, "participants": 5})
		if err != nil {
			t.Fatalf("pulsar.keygen: %v", err)
		}
		var kgR struct{ PublicKey string }
		_ = json.Unmarshal(kg, &kgR)
		gk, _ := hex.DecodeString(kgR.PublicKey)
		sg, err := rpcCall(hs.URL, "pulsar.sign", map[string]any{
			"messageHex": hex.EncodeToString(msg), "pubKeyHex": kgR.PublicKey,
		})
		if err != nil {
			t.Fatalf("pulsar.sign: %v", err)
		}
		var sgR struct{ SignatureHex string }
		_ = json.Unmarshal(sg, &sgR)
		sig, _ := hex.DecodeString(sgR.SignatureHex)

		fipsPK, _ := stripFrame(gk, magicPULG, "pulsar")
		fipsSig, _ := stripFrame(sig, magicPULS, "pulsar")
		var pk circlmldsa65.PublicKey
		if err := pk.UnmarshalBinary(fipsPK); err != nil {
			t.Fatalf("circl mldsa65 UnmarshalBinary: %v", err)
		}
		ok := circlmldsa65.Verify(&pk, msg, nil, fipsSig)
		t.Logf("PULSAR  wire-gk-sha256: %s (len=%d)", hexShort(sha256.Sum256(gk)), len(gk))
		t.Logf("PULSAR  wire-sig-sha256: %s (len=%d)", hexShort(sha256.Sum256(sig)), len(sig))
		t.Logf("PULSAR  fips-pk-sha256 : %s (len=%d)", hexShort(sha256.Sum256(fipsPK)), len(fipsPK))
		t.Logf("PULSAR  fips-sig-sha256: %s (len=%d)", hexShort(sha256.Sum256(fipsSig)), len(fipsSig))
		t.Logf("PULSAR  circl.Verify(&pk, msg, nil, fipsSig) = %v", ok)
		if !ok {
			t.Errorf("PULSAR byte-identity broken: circl.Verify rejected dispatcher signature")
		}
	}

	// --- magnetar ---
	{
		kg, err := rpcCall(hs.URL, "magnetar.keygen", map[string]any{"threshold": 5, "participants": 5})
		if err != nil {
			t.Fatalf("magnetar.keygen: %v", err)
		}
		var kgR struct{ PublicKey string }
		_ = json.Unmarshal(kg, &kgR)
		gk, _ := hex.DecodeString(kgR.PublicKey)
		sg, err := rpcCall(hs.URL, "magnetar.sign", map[string]any{
			"messageHex": hex.EncodeToString(msg), "pubKeyHex": kgR.PublicKey,
		})
		if err != nil {
			t.Fatalf("magnetar.sign: %v", err)
		}
		var sgR struct{ SignatureHex string }
		_ = json.Unmarshal(sg, &sgR)
		sig, _ := hex.DecodeString(sgR.SignatureHex)

		fipsPK, _ := stripFrame(gk, magicMAGG, "magnetar")
		fipsSig, _ := stripFrame(sig, magicMAGS, "magnetar")
		pk := circlslhdsa.PublicKey{ID: circlslhdsa.SHAKE_192s}
		if err := pk.UnmarshalBinary(fipsPK); err != nil {
			t.Fatalf("circl slhdsa UnmarshalBinary: %v", err)
		}
		ok := circlslhdsa.Verify(&pk, circlslhdsa.NewMessage(msg), fipsSig, nil)
		t.Logf("MAGNTR  wire-gk-sha256: %s (len=%d)", hexShort(sha256.Sum256(gk)), len(gk))
		t.Logf("MAGNTR  wire-sig-sha256: %s (len=%d)", hexShort(sha256.Sum256(sig)), len(sig))
		t.Logf("MAGNTR  fips-pk-sha256 : %s (len=%d)", hexShort(sha256.Sum256(fipsPK)), len(fipsPK))
		t.Logf("MAGNTR  fips-sig-sha256: %s (len=%d)", hexShort(sha256.Sum256(fipsSig)), len(fipsSig))
		t.Logf("MAGNTR  circl.Verify(&pk, NewMessage(msg), fipsSig, nil) = %v", ok)
		if !ok {
			t.Errorf("MAGNETAR byte-identity broken: circl.Verify rejected dispatcher signature")
		}
	}

	// --- corona ---
	{
		kg, err := rpcCall(hs.URL, "corona.keygen", map[string]any{"threshold": 3, "participants": 5})
		if err != nil {
			t.Fatalf("corona.keygen: %v", err)
		}
		var kgR struct{ PublicKey string }
		_ = json.Unmarshal(kg, &kgR)
		gk, _ := hex.DecodeString(kgR.PublicKey)
		sg, err := rpcCall(hs.URL, "corona.sign", map[string]any{
			"messageHex": hex.EncodeToString(msg), "pubKeyHex": kgR.PublicKey,
		})
		if err != nil {
			t.Fatalf("corona.sign: %v", err)
		}
		var sgR struct{ SignatureHex string }
		_ = json.Unmarshal(sg, &sgR)
		sig, _ := hex.DecodeString(sgR.SignatureHex)

		ok := coronaThreshold.VerifyBytes(gk, string(msg), sig)
		t.Logf("CORONA  wire-gk-sha256: %s (len=%d)", hexShort(sha256.Sum256(gk)), len(gk))
		t.Logf("CORONA  wire-sig-sha256: %s (len=%d)", hexShort(sha256.Sum256(sig)), len(sig))
		t.Logf("CORONA  coronaThreshold.VerifyBytes(gk, string(msg), sig) = %v", ok)
		if !ok {
			t.Errorf("CORONA byte-identity broken: VerifyBytes rejected dispatcher signature")
		}
	}
}

func hexShort(h [32]byte) string {
	return hex.EncodeToString(h[:])
}
