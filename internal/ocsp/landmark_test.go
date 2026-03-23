package ocsp

import (
	"crypto"
	"merkle-ocsp/internal/cert"
	"merkle-ocsp/internal/tree"
	"testing"
)

// make into actual test
func TestLandmarkLog(t *testing.T) {
	// -- Build a landmark chain --

	// ==========================================
	// Step 0: Initial Setup
	// ==========================================

	// Generate a CA-keypair  (currently RSA, TBC)
	ca, err := cert.NewRootCertificateAndKey(2048)
	if err != nil {
		t.Fatalf("creating key or cert: %v", err)
	}
	keyPair := ca.PKey

	// Create an empty Log
	log, err := tree.NewLog()
	if err != nil {
		t.Errorf("creating empty Log")
	}

	// Create a "global" revocation-tree that lives across epochs
	activeRevokedTree := tree.NewSparse()

	// ==========================================
	// Step 1: Epoch 1 (Hour 0 to 1) (e.g)
	// ==========================================

	issuedCerts, err := cert.NewListRandomCertificatesWithKey(5, keyPair)
	issuedCerts = cert.HashList(issuedCerts)
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
	signedlm1, err := lm1.NewSignedHead(keyPair, crypto.SHA256)

	if signedlm1 == nil {
		t.Fatalf("signedlm1 should not be nil")
	}
	// Stat tracking for hour 1-2
	issuedCerts2, err := cert.NewListRandomCertificatesWithKey(5, keyPair)
	issuedCerts2 = cert.HashList(issuedCerts2)
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
	_, err = lm2.NewSignedHead(keyPair, crypto.SHA256)
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
		lm2Proof, err := lm2.NewLandmarkProof(issuedCerts2[1])
		if err != nil {
			t.Fatalf("creating proof for valid certificate: %v", err)
		}
		if lm2Proof.CombinedProof.IssueProof == nil || lm2Proof.CombinedProof == nil {
			t.Fatal("expected non-nil proof for valid certificate")
		}
		revokedCert := issuedCerts2[0]
		revokedProof, err := lm2.NewLandmarkProof(revokedCert)
		if err != nil {
			t.Fatalf("creating proof for revoked certificate: %v", err)
		}
		if revokedProof == nil || revokedProof.CombinedProof == nil {
			t.Fatal("expected non-nil proof for revoked certificate", err)
		}
	})

	t.Run("Epoch 2, Check Merkle Responses", func(t *testing.T) {
		// Test 1: Revoked (index 0 → even → revoked)
		// Pass raw cert bytes; NewResponse/getStatus handle hashing internally.
		responseRevoked, err := NewResponse(issuedCerts2[0], lm2)
		if err != nil {
			t.Fatalf("creating merkle response for revoked cert: %v", err)
		}
		if responseRevoked.Status != Revoked {
			t.Errorf("expected status Revoked (%d), got %d", Revoked, responseRevoked.Status)
		}

		// Test 2: Good (index 1 → odd → not revoked)
		responseGood, err := NewResponse(issuedCerts2[1], lm2)
		if err != nil {
			t.Fatalf("creating merkle response for good cert: %v", err)
		}
		if responseGood.Status != Good {
			t.Errorf("expected status Good (%d), got %d", Good, responseGood.Status)
		}
		/*
			// unknown proof Not implemented

			// Test 3: Unknown (never issued)
			unknownCert := []byte("this-cert-was-never-issued")
			hash := cert.HashCert(unknownCert)
			responseUnknown, err := NewResponse(hash, lm2)
			if err != nil {
				t.Fatalf("creating merkle response for unknown cert: %v", err)
			}
			if responseUnknown.Status != Unknown {
				t.Errorf("expected status Unknown (%d), got %d", Unknown, responseUnknown.Status)
			}
		*/

	})
	// Freeze Landmark 2 (ONLY WHEN CREATING NEW EPOCH)
	//landmark2.Ctree.revSMT = activeRevokedTree.Freeze()

}
