package ocsp

import (
	"crypto"
	"merkle-ocsp/internal/tree"
	"merkle-ocsp/internal/util"
	"testing"
	"time"
)

// make into actual test
func TestLandmarkLog(t *testing.T) {

	ca, err := util.NewRootCertificateAndKey(2048)
	if err != nil {
		t.Fatalf("creating key or util: %v", err)
	}
	keyPair := ca.PKey

	log, err := tree.NewLog()
	if err != nil {
		t.Errorf("creating empty Log")
	}

	activeRevokedTree := tree.NewSparse()

	issuedCerts, err := util.NewListRandomCertificatesWithKey(5, keyPair)
	issuedCerts = util.HashList(issuedCerts)
	if err != nil {
		t.Fatalf("creating certs using key: %v", err)
	}

	// Revoke some of them
	var revokedCerts [][]byte
	for i, b := range issuedCerts {
		if i%2 == 0 {
			revokedCerts = append(revokedCerts, b)
		}
	}

	// Create a tree for the issued certs  & pass in the previously created revocation-tree
	firstTree, err := tree.NewCombined(issuedCerts, revokedCerts, activeRevokedTree)
	if err != nil {
		t.Fatalf("adding certs to first tree: %v", err)
	}

	// From the issuelog and combinedtree, create a landmark
	lm1, err := NewLandmark(log, firstTree)
	if err != nil {
		t.Fatalf("creating landmark")
	}
	// Sign the Log for distribution
	signedlm1, err := lm1.NewSignedHead(keyPair, crypto.SHA256, time.Hour)

	if signedlm1 == nil {
		t.Fatalf("signedlm1 should not be nil")
	}
	// Stat tracking for hour 1-2
	issuedCerts2, err := util.NewListRandomCertificatesWithKey(5, keyPair)
	issuedCerts2 = util.HashList(issuedCerts2)
	if err != nil {
		t.Fatalf("creating certs using key: %v", err)
	}
	// Revoke some of them
	var revokedCerts2 [][]byte
	for i, b := range issuedCerts2 {
		if i%2 == 0 {
			revokedCerts2 = append(revokedCerts2, b)
		}
	}
	// Create a new combined tree for the 2nd hour / 2nd epoch, making sure to pass the same revocation initially created
	secondTree, err := tree.NewCombined(issuedCerts2, revokedCerts2, activeRevokedTree)
	if err != nil {
		t.Fatalf("adding certs to 2nd tree: %v", err)
	}

	err = log.AppendToLog(secondTree.Root)

	if err != nil {
		t.Errorf("adding combinedtree to Log, %v", err)
	}
	lm2, err := NewLandmark(log, secondTree)
	if err != nil {
		t.Error("creating landmark 2")
	}
	_, err = lm2.NewSignedHead(keyPair, crypto.SHA256, time.Hour)
	if err != nil {
		t.Errorf("signing head 2 %v", err)
	}

	t.Run("Epoch 2, State Persistence (Old Revocations)", func(t *testing.T) {
		inTree, err := activeRevokedTree.Has(issuedCerts[0])
		if err != nil {
			t.Fatalf("failed to check active tree: %v", err)
		}
		if !inTree {
			t.Fatalf("Certificate revoked in Epoch 1 is missing from Epoch 2's active tree")
		}
	})

	t.Run("Epoch 2, Generate Proofs", func(t *testing.T) {
		lm2Proof, err := lm2.NewLandmarkProof(issuedCerts2[1], lm2)
		if err != nil {
			t.Fatalf("creating proof for valid certificate: %v", err)
		}
		if lm2Proof.CombinedProof.IssueProof == nil || lm2Proof.CombinedProof == nil {
			t.Fatal("expected non-nil proof for valid certificate")
		}
		revokedCert := issuedCerts2[0]
		revokedProof, err := lm2.NewLandmarkProof(revokedCert, lm2)
		if err != nil {
			t.Fatalf("creating proof for revoked certificate: %v", err)
		}
		if revokedProof == nil || revokedProof.CombinedProof == nil {
			t.Fatal("expected non-nil proof for revoked certificate", err)
		}
	})

	t.Run("Epoch 2, Check Merkle Responses", func(t *testing.T) {
		responseRevoked, err := NewResponse(issuedCerts2[0], lm2, lm2)
		if err != nil {
			t.Fatalf("creating merkle response for revoked util: %v", err)
		}
		if responseRevoked.Status != Revoked {
			t.Errorf("expected status Revoked (%d), got %d", Revoked, responseRevoked.Status)
		}
		responseGood, err := NewResponse(issuedCerts2[1], lm2, lm2)
		if err != nil {
			t.Fatalf("creating merkle response for good util: %v", err)
		}
		if responseGood.Status != Good {
			t.Errorf("expected status Good (%d), got %d", Good, responseGood.Status)
		}
		/*
			// unknown proof Not implemented

			// Test 3: Unknown (never issued)
			unknownCert := []byte("this-util-was-never-issued")
			hash := util.HashCert(unknownCert)
			responseUnknown, err := NewResponse(hash, lm2, lm2)
			if err != nil {
				t.Fatalf("creating merkle response for unknown util: %v", err)
			}
			if responseUnknown.Status != Unknown {
				t.Errorf("expected status Unknown (%d), got %d", Unknown, responseUnknown.Status)
			}
		*/

	})
	// Freeze Landmark 2 (ONLY WHEN CREATING NEW EPOCH)
	//landmark2.CTree.revSMT = activeRevokedTree.Freeze()

}
