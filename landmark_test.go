package main

import (
	"bytes"
	"crypto"
	"testing"
)

// make into actual test
func TestLandmarkChain(t *testing.T) {
	// -- Build a landmark chain --
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

	// Hour 0 to 1: collect issued and revoked certificates
	issuedCerts, err := NewListRandomCertificatesWithKey(50, keyPair)
	if err != nil {
		t.Fatalf("creating certs using key: %v", err)
	}

	var revokedCerts [][]byte
	for i, b := range issuedCerts {
		if i%2 == 0 {
			revokedCerts = append(revokedCerts, b)
		}
	}

	// Create a tree for the issued certs and add the revoked certs
	firstTree, err := NewCombinedTree(issuedCerts, revokedCerts)
	if err != nil {
		t.Fatalf("adding certs to first tree: %v", err)
	}

	// Create a landmark for hour: 1 using initEpoch and firstTree
	firstLandmark, err := NewLandmark(initEpoch, firstTree, crypto.SHA256, keyPair)
	if err != nil {
		t.Fatalf("error creating first landmark: %v", err)
	}

	t.Run("First Landmark Integrity", func(t *testing.T) {
		if firstLandmark.lastLandmark != initEpoch {
			t.Error("expected first landmark's previous landmark to be initEpoch")
		}
		if len(firstLandmark.head) == 0 {
			t.Error("expected landmark head to be populated")
		}
		if len(firstLandmark.signedHead) == 0 {
			t.Error("expected landmark signed head to be populated")
		}
	})

	// Hour 1 to 2: collect issued and revoked certificates
	issuedCerts2, err := NewListRandomCertificatesWithKey(50, keyPair)
	if err != nil {
		t.Fatalf("creating certs using key: %v", err)
	}

	var revokedCerts2 [][]byte
	for i, b := range issuedCerts2 {
		if i%2 == 0 {
			revokedCerts2 = append(revokedCerts2, b)
		}
	}

	secondTree, err := NewCombinedTree(issuedCerts2, revokedCerts2)
	if err != nil {
		t.Fatalf("adding certs to second tree: %v", err)
	}

	// Create second landmark
	secondLandmark, err := NewLandmark(firstLandmark, secondTree, crypto.SHA256, keyPair)
	if err != nil {
		t.Fatalf("error creating second landmark: %v", err)
	}

	t.Run("Second Landmark Integrity", func(t *testing.T) {
		if secondLandmark.lastLandmark != firstLandmark {
			t.Error("expected second landmark's previous landmark to be firstLandmark")
		}
		if !bytes.Equal(secondLandmark.lastLandmark.head, firstLandmark.head) {
			t.Error("expected second landmark's reference to previous head to match first landmark's head")
		}
	})

	t.Run("Generate Proof for Good Certificate", func(t *testing.T) {
		// issuedCerts2[1] is an odd index, therefore NOT added to revokedCerts2
		goodCert := issuedCerts2[1]
		issuedProof, err := secondLandmark.newLandmarkProof(goodCert)
		if err != nil {
			t.Fatalf("creating proof for valid certificate: %v", err)
		}
		if issuedProof == nil || issuedProof.combinedProof == nil {
			t.Fatal("expected non-nil proof for valid certificate")
		}

		if !bytes.Equal(issuedProof.prevUnsignedHashHead, firstLandmark.head) {
			t.Error("expected proof to contain correct previous landmark head")
		}
	})

	t.Run("Generate Proof for Revoked Certificate", func(t *testing.T) {
		// issuedCerts2[0] is an even index, therefore added to revokedCerts2
		revokedCert := issuedCerts2[0]
		revokedProof, err := secondLandmark.newLandmarkProof(revokedCert)
		if err != nil {
			t.Fatalf("creating proof for revoked certificate: %v", err)
		}
		if revokedProof == nil || revokedProof.combinedProof == nil {
			t.Fatal("expected non-nil proof for revoked certificate")
		}
	})

	t.Run("Check Merkle Responses via Landmark", func(t *testing.T) {
		responseRevoked, err := NewMerkleResponse(issuedCerts2[0], secondLandmark)
		if err != nil {
			t.Fatalf("creating merkle response for revoked cert: %v", err)
		}
		if responseRevoked.status != Revoked {
			t.Errorf("expected status Revoked, got %v", responseRevoked.status)
		}

		responseGood, err := NewMerkleResponse(issuedCerts2[1], secondLandmark)
		if err != nil {
			t.Fatalf("creating merkle response for good cert: %v", err)
		}
		if responseGood.status != Good {
			t.Errorf("expected status Good, got %v", responseGood.status)
		}
	})
}
