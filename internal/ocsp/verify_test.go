package ocsp

import (
	"crypto"
	"merkle-ocsp/internal/tree"
	"merkle-ocsp/internal/util"
	"testing"
	"time"
)

func setup(t *testing.T) ([][]byte, *Landmark, *SignedLandmark) {
	t.Helper()
	ca, err := util.NewRootCertificateAndKey(2048)
	if err != nil {
		t.Fatalf("setup: key gen: %v", err)
	}
	certs, err := util.NewListRandomCertificatesWithKey(6, ca.PKey)
	if err != nil {
		t.Fatalf("setup: util gen: %v", err)
	}
	certs = util.HashList(certs)

	log, _ := tree.NewLog()
	revTree := tree.NewSparse()
	// Revoke some certs
	var revoked [][]byte
	for i, c := range certs {
		if i%2 == 0 {
			revoked = append(revoked, c)
		}
	}
	cTree, err := tree.NewCombined(certs, revoked, revTree)
	if err != nil {
		t.Fatalf("setup: combined tree: %v", err)
	}
	lm, err := NewLandmark(log, cTree)
	if err != nil {
		t.Fatalf("setup: landmark: %v", err)
	}
	sl, err := lm.NewSignedHead(ca.PKey, crypto.SHA256, time.Hour)
	if err != nil {
		t.Fatalf("setup: signed head: %v", err)
	}
	return certs, lm, sl
}
func TestVerifyNilResponse(t *testing.T) {
	_, _, sl := setup(t)
	ok, err := Verify(nil, sl, []byte("x"), time.Now())
	if ok || err == nil {
		t.Fatal("expected error for nil response")
	}
}

func TestVerifyNilSignedLandmark(t *testing.T) {
	certs, lm, _ := setup(t)
	response, _ := NewResponse(certs[1], lm, lm)
	ok, err := Verify(response, nil, certs[1], time.Now())
	if ok || err == nil {
		t.Fatal("expected error for nil SignedLandmark")
	}
}

func TestVerifyNilProof(t *testing.T) {
	_, _, sl := setup(t)
	resp := &Response{Status: Good, Proof: nil}
	ok, err := Verify(resp, sl, []byte("x"), time.Now())
	if ok || err == nil {
		t.Fatal("expected error for nil proof")
	}
}
func TestVerifyGood(t *testing.T) {
	certs, lm, sl := setup(t)
	goodCert := certs[1]
	resp, err := NewResponse(goodCert, lm, lm)
	if err != nil {
		t.Fatalf("newResponse: %v", err)
	}
	if resp.Status != Good {
		t.Fatalf("expected Good status, got %d", resp.Status)
	}
	ok, err := Verify(resp, sl, goodCert, time.Now())
	if !ok || err != nil {
		t.Fatalf("Verify(Good) failed: ok=%t err=%v", ok, err)
	}
}
func TestVerifyGoodWrongHash(t *testing.T) {
	certs, lm, sl := setup(t)
	resp, _ := NewResponse(certs[1], lm, lm)
	ok, _ := Verify(resp, sl, []byte("wrong-hash"), time.Now())
	if ok {
		t.Fatal("expected Verify to fail when hash doesn't match proof")
	}

}
func TestVerifyRevoked(t *testing.T) {
	certs, lm, sl := setup(t)
	revokedCert := certs[0]
	resp, err := NewResponse(revokedCert, lm, lm)
	if err != nil {
		t.Fatalf("newResponse: %v", err)
	}
	if resp.Status != Revoked {
		t.Fatalf("expected Revoked status, got %d", resp.Status)
	}
	ok, err := Verify(resp, sl, revokedCert, time.Now())
	if !ok || err != nil {
		t.Fatalf("Verify(Revoked) failed: ok=%t err=%v", ok, err)
	}
}

func TestVerifyRevokedWrongHash(t *testing.T) {
	certs, lm, sl := setup(t)
	resp, _ := NewResponse(certs[0], lm, lm)
	ok, err := Verify(resp, sl, []byte("wrong-hash"), time.Now())
	if ok {
		t.Fatal("expected Verify to fail when hash doesn't match revocation proof")
	}
	_ = err
}
func TestVerifyUnknownNilNonIssueProof(t *testing.T) {
	_, _, sl := setup(t)
	resp := &Response{
		Status: Unknown,
		Proof: &LandmarkProof{
			CombinedProof: &CombinedProof{
				NonIssueProof: nil,
			},
		},
	}
	ok, err := Verify(resp, sl, []byte("ghost"), time.Now())
	if ok || err == nil {
		t.Fatal("expected error: Unknown status requires NonIssueProof")
	}
}
func TestVerify_Unknown_TamperedAsGood(t *testing.T) {
	_, lm, sl := setup(t)
	resp, _ := NewResponse([]byte("never-issued"), lm, lm)
	resp.Status = Good
	ok, err := Verify(resp, sl, []byte("never-issued"), time.Now())
	if ok {
		t.Fatal("expected Verify to reject a forged Good status on an Unknown response")
	}
	_ = err
}

func TestVerify_Unknown_TamperedAsRevoked(t *testing.T) {
	_, lm, sl := setup(t)
	resp, _ := NewResponse([]byte("never-issued"), lm, lm)
	resp.Status = Revoked
	ok, err := Verify(resp, sl, []byte("never-issued"), time.Now())
	if ok {
		t.Fatal("expected Verify to reject a forged Revoked status on an Unknown response")
	}
	_ = err
}
func TestVerifyUnknownGoodResponseClaimingUnknown(t *testing.T) {
	certs, lm, sl := setup(t)
	resp, _ := NewResponse(certs[1], lm, lm)
	resp.Status = Unknown
	ok, err := Verify(resp, sl, certs[1], time.Now())
	if ok {
		t.Fatal("expected Verify to reject Unknown status when util is actually in the issue tree")
	}
	_ = err
}

/*


func TestVerifyUnknownEndToEndCurrentlyFails(t *testing.T) {
	_, lm, sl := setup(t)
	unknownCert := []byte("never-issued")
	resp, err := newResponse(unknownCert, lm, lm)
	if err != nil {
		t.Fatalf("newResponse: %v", err)
	}
	if resp.Status != Unknown {
		t.Fatalf("expected Unknown status, got %d", resp.Status)
	}
	ok, err := Verify(resp, sl, unknownCert)
	if !ok || err != nil {
		t.Fatalf("Verify(Unknown) failed: ok=%t err=%v", ok, err)
	}
} */
