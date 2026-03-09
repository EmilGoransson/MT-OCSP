package main

import (
	"crypto"
	"fmt"
	"testing"
)

// make into actual test
func TestLandmarkChain(t *testing.T) {

	// -- Build a landmark chain --
	// Generate a CA-keypair (currently RSA, TBC)
	ca, err := NewRootCertificateAndKey(2048)
	if err != nil {
		fmt.Println(err)
	}
	var keyPair = ca.pKey

	// Start head (empty tree) & actual tree
	initEpoch := NewEmptyTree()

	// Hour 0 to 1: collect issued and revoked certificates (can use NewCertificate)

	issuedCerts, err := NewListRandomCertificatesWithKey(5, keyPair)
	var revokedCerts [][]byte
	for i, b := range issuedCerts {
		if i%2 == 0 {
			revokedCerts = append(revokedCerts, b)
		}
	}
	// Hour: 0-1, create a tree for the issued certs
	// TODO: add so that u can add revoked certs at the same time as issued certs
	firstEpoch, err := NewCombinedTree(issuedCerts, nil)
	//  Hour: 0-1,  and add the revoked certs
	_, err = firstEpoch.addBulkRevocationToTree(revokedCerts)

	// Create a landmark for hour: 1 using initEpoch and firstEpoch
	firstLandmark, err := NewLandmark(initEpoch, firstEpoch, crypto.SHA256, keyPair)

	// TODO: Save landmark to DB or smht
	fmt.Println("save to DB", firstLandmark)

	// New iteration
	// Hour 1 to 2: collect issued and revoked certificates
	issuedCerts2 := [][]byte{
		[]byte("issued-id-005"),
		[]byte("issued-id-006"),
	}
	revokedCerts2 := [][]byte{
		[]byte("issued-id-006"),
	}
	// Hour: 1-2, Create a tree for the issued certs and add the revoked certs
	secondEpoch, _ := NewCombinedTree(issuedCerts2, revokedCerts2)
	// Create second landmark
	secondLandmark, err := NewLandmark(firstEpoch, secondEpoch, crypto.SHA256, keyPair)

	// TODO: Save landmark to DB or smht
	fmt.Println("save to DB", secondLandmark)

	if err != nil {
		fmt.Errorf("error creating first epoch, %w", err)
	}

	// Generate proof for LM1
	certToCheck := []byte("issued-id-002")
	proof, err := firstLandmark.newLandmarkProof(certToCheck)
	if err != nil {
		fmt.Errorf("creating proof for issued 002 %w", err)
	}

	fmt.Println(proof)

	// TODO: Validate the landmark proof

}
