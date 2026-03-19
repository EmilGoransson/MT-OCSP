package main

import (
	"crypto"
	"testing"
)

// make into actual test
func TestLandmarkLog(t *testing.T) {
	// -- Build a landmark chain --

	// ==========================================
	// Step 0: Initial Setup
	// ==========================================

	// Generate a CA-keypair  (currently RSA, TBC)
	ca, err := NewRootCertificateAndKey(2048)
	if err != nil {
		t.Fatalf("creating key or cert: %v", err)
	}
	keyPair := ca.pKey

	// Create an empty log
	log, err := NewAppendLog()
	if err != nil {
		t.Errorf("creating empty log")
	}

	// Create a "global" revocation-tree that lives across epochs
	activeRevokedTree := NewSparseMerkle()

	// ==========================================
	// Step 1: Epoch 1 (Hour 0 to 1) (e.g)
	// ==========================================

	issuedCerts, err := NewListRandomCertificatesWithKey(5, keyPair)
	issuedCerts = HashList(issuedCerts)
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
	firstTree, err := NewCombinedTree(issuedCerts, revokedCerts, activeRevokedTree)
	if err != nil {
		t.Fatalf("adding certs to first tree: %v", err)
	}

	// From the issuelog and combinedtree, create a landmark
	lm1, err := NewLandmark(log, firstTree)
	if err != nil {
		t.Fatalf("creating landmark")
	}
	// Sign the log for distribution
	signedlm1, err := lm1.NewSignedHead(keyPair, crypto.SHA256)

	if signedlm1 == nil {
		t.Fatalf("signedlm1 should not be nil")
	}
	// Stat tracking for hour 1-2
	issuedCerts2, err := NewListRandomCertificatesWithKey(5, keyPair)
	issuedCerts2 = HashList(issuedCerts2)
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
	secondTree, err := NewCombinedTree(issuedCerts2, revokedCerts2, activeRevokedTree)
	if err != nil {
		t.Fatalf("adding certs to 2nd tree: %v", err)
	}

	err = log.appendToLog(secondTree.root)

	if err != nil {
		t.Errorf("adding combinedtree to log, %v", err)
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
		if lm2Proof.combinedProof.issueProof == nil || lm2Proof.combinedProof == nil {
			t.Fatal("expected non-nil proof for valid certificate")
		}
		revokedCert := issuedCerts2[0]
		revokedProof, err := lm2.NewLandmarkProof(revokedCert)
		if err != nil {
			t.Fatalf("creating proof for revoked certificate: %v", err)
		}
		if revokedProof == nil || revokedProof.combinedProof == nil {
			t.Fatal("expected non-nil proof for revoked certificate", err)
		}
	})

	t.Run("Epoch 2, Check Merkle Responses", func(t *testing.T) {
		// Test 1: Revoked (index 0 → even → revoked)
		// Pass raw cert bytes; NewMerkleResponse/getStatus handle hashing internally.
		responseRevoked, err := NewMerkleResponse(issuedCerts2[0], lm2)
		if err != nil {
			t.Fatalf("creating merkle response for revoked cert: %v", err)
		}
		if responseRevoked.status != Revoked {
			t.Errorf("expected status Revoked (%d), got %d", Revoked, responseRevoked.status)
		}

		// Test 2: Good (index 1 → odd → not revoked)
		responseGood, err := NewMerkleResponse(issuedCerts2[1], lm2)
		if err != nil {
			t.Fatalf("creating merkle response for good cert: %v", err)
		}
		if responseGood.status != Good {
			t.Errorf("expected status Good (%d), got %d", Good, responseGood.status)
		}

		// Test 3: Unknown (never issued)
		unknownCert := []byte("this-cert-was-never-issued")
		hash := HashCert(unknownCert)
		responseUnknown, err := NewMerkleResponse(hash, lm2)
		if err != nil {
			t.Fatalf("creating merkle response for unknown cert: %v", err)
		}
		if responseUnknown.status != Unknown {
			t.Errorf("expected status Unknown (%d), got %d", Unknown, responseUnknown.status)
		}
	})
	// Freeze Landmark 2 (ONLY WHEN CREATING NEW EPOCH)
	//landmark2.cTree.revSMT = activeRevokedTree.Freeze()

}
