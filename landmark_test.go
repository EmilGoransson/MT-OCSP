package main

import (
	"bytes"
	"crypto"
	"testing"
)

// make into actual test
func TestLandmarkChain(t *testing.T) {
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

	// Start head (empty tree)
	initEpoch := NewEmptyLandmark(crypto.SHA256)
	if initEpoch == nil {
		t.Fatal("expected initEpoch to not be nil")
	}
	// Create a "global" revocation-tree that lives across epochs
	activeRevokedTree := NewSparseMerkle()

	// ==========================================
	// Step 1: Epoch 1 (Hour 0 to 1) (e.g)
	// ==========================================

	issuedCerts, err := NewListRandomCertificatesWithKey(5, keyPair)
	if err != nil {
		t.Fatalf("creating certs using key: %v", err)
	}

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

	landmark1, err := NewLandmark(initEpoch, firstTree, crypto.SHA256, keyPair)
	if err != nil {
		t.Fatalf("error creating first landmark: %v", err)
	}

	t.Run(" Epoch 1, Landmark Integrity", func(t *testing.T) {
		if landmark1.lastLandmark != initEpoch {
			t.Error("expected first landmark's previous landmark to be initEpoch")
		}
		if len(landmark1.head) == 0 {
			t.Error("expected landmark head to be populated")
		}
		if len(landmark1.signedHead) == 0 {
			t.Error("expected landmark signed head to be populated")
		}
	})

	// To be distributed
	// fmt.Println(landmark1.signedHead)

	// ==========================================
	// Step 2: Freezing Epoch 1
	// ==========================================
	// Freeze landmark 1 revocation-tree since we are creating a new one
	// Calculates hash & sets smt = nil
	landmark1.cTree.revSMT = activeRevokedTree.Freeze()

	// ==========================================
	// Step 3: Epoch 2 (Hour 1 to 2)
	// ==========================================
	issuedCerts2, err := NewListRandomCertificatesWithKey(8, keyPair)
	if err != nil {
		t.Fatalf("creating certs using key: %v", err)
	}

	var revokedCerts2 [][]byte
	for i, b := range issuedCerts2 {
		if i%2 == 0 {
			revokedCerts2 = append(revokedCerts2, b)
		}
	}
	// activeRevokedTree passed in here
	secondTree, err := NewCombinedTree(issuedCerts2, revokedCerts2, activeRevokedTree)
	if err != nil {
		t.Fatalf("adding certs to second tree: %v", err)
	}

	landmark2, err := NewLandmark(landmark1, secondTree, crypto.SHA256, keyPair)
	if err != nil {
		t.Fatalf("error creating second landmark: %v", err)
	}

	t.Run("Second Landmark Integrity", func(t *testing.T) {
		if landmark2.lastLandmark != landmark1 {
			t.Error("expected second landmark's previous landmark to be landmark1")
		}
		if !bytes.Equal(landmark2.lastLandmark.head, landmark1.head) {
			t.Error("expected second landmark's reference to previous head to match first landmark's head")
		}
	})
	t.Run("Epoch 2, Landmark Integrity", func(t *testing.T) {
		if landmark2.lastLandmark != landmark1 {
			t.Error("expected second landmark's previous landmark to be landmark1")
		}
		if !bytes.Equal(landmark2.lastLandmark.head, landmark1.head) {
			t.Error("expected second landmark's reference to previous head to match first landmark's head")
		}
	})

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
		goodCert := issuedCerts2[1]
		issuedProof, err := landmark2.newLandmarkProof(goodCert)
		if err != nil {
			t.Fatalf("creating proof for valid certificate: %v", err)
		}
		if issuedProof == nil || issuedProof.combinedProof == nil {
			t.Fatal("expected non-nil proof for valid certificate")
		}
		if !bytes.Equal(issuedProof.prevUnsignedHashHead, landmark1.head) {
			t.Error("expected proof to contain correct previous landmark head")
		}

		revokedCert := issuedCerts2[0]
		revokedProof, err := landmark2.newLandmarkProof(revokedCert)
		if err != nil {
			t.Fatalf("creating proof for revoked certificate: %v", err)
		}
		if revokedProof == nil || revokedProof.combinedProof == nil {
			t.Fatal("expected non-nil proof for revoked certificate")
		}
	})

	t.Run("Epoch 2, Check Merkle Responses", func(t *testing.T) {
		responseRevoked, err := NewMerkleResponse(issuedCerts2[0], landmark2)
		if err != nil {
			t.Fatalf("creating merkle response for revoked cert: %v", err)
		}
		if responseRevoked.status != Revoked {
			t.Errorf("expected status Revoked, got %v", responseRevoked.status)
		}

		// Test 2: Good
		responseGood, err := NewMerkleResponse(issuedCerts2[1], landmark2)
		if err != nil {
			t.Fatalf("creating merkle response for good cert: %v", err)
		}
		if responseGood.status != Good {
			t.Errorf("expected status Good, got %v", responseGood.status)
		}

		// Test 3: Unknown
		unknownCert := []byte("this-cert-was-never-issued")
		responseUnknown, err := NewMerkleResponse(unknownCert, landmark2)
		if err != nil {
			t.Fatalf("creating merkle response for unknown cert: %v", err)
		}
		if responseUnknown.status != Unknown {
			t.Errorf("expected status Unknown, got %v", responseUnknown.status)
		}
	})
	// Freeze Landmark 2 (ONLY WHEN CREATING NEW EPOCH)
	//landmark2.cTree.revSMT = activeRevokedTree.Freeze()
}
