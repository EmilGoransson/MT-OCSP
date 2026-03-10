package main

import (
	"bytes"
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
		t.Fatalf("creating key or cert %v", err)
	}
	var keyPair = ca.pKey

	// Start head (empty tree) & actual tree
	initEpoch := NewEmptyLandmark(crypto.SHA256)

	// Hour 0 to 1: collect issued and revoked certificates (can use NewCertificate)
	// when n = large it bugs for som e reason in debugger
	issuedCerts, err := NewListRandomCertificatesWithKey(200, keyPair)
	if err != nil {
		t.Fatalf("creating cert using key %v", err)
	}

	var revokedCerts [][]byte
	for i, b := range issuedCerts {
		if i%2 == 0 {
			revokedCerts = append(revokedCerts, b)
		}
	}
	// Hour: 0-1, create a tree for the issued certs
	firstTree, err := NewCombinedTree(issuedCerts, nil)

	if err != nil {
		t.Fatalf("adding certs to tree ")
	}
	//  Hour: 0-1,  and add the revoked certs
	_, err = firstTree.addBulkRevocationToTree(revokedCerts)

	// Create a landmark for hour: 1 using initEpoch and firstEpoch
	firstLandmark, err := NewLandmark(initEpoch, firstTree, crypto.SHA256, keyPair)

	// TODO: Save landmark to DB or smht
	//fmt.Println("save to DB", firstLandmark)

	// New iteration
	// Hour 1 to 2: collect issued and revoked certificates
	issuedCerts2, err := NewListRandomCertificatesWithKey(200, keyPair)
	if err != nil {
		t.Fatalf("creating cert using key %v", err)
	}

	var revokedCerts2 [][]byte
	for i, b := range issuedCerts2 {
		if i%2 == 0 {
			revokedCerts2 = append(revokedCerts2, b)
		}
	}
	fmt.Println(bytes.Compare(revokedCerts2[0], revokedCerts2[1]))
	/*
		this bugs out? why?

			issuedCerts2 := [][]byte{
				[]byte("issued-id-005"),
				[]byte("issued-id-006"),
			}
			revokedCerts2 := [][]byte{
				[]byte("issued-id-006"),
			}
	*/
	// Hour: 1-2, Create a tree for the issued certs and add the revoked certs
	secondTree, _ := NewCombinedTree(issuedCerts2, revokedCerts2)

	// Create second landmark
	secondLandmark, err := NewLandmark(firstLandmark, secondTree, crypto.SHA256, keyPair)

	// TODO: Save landmark to DB or smht
	fmt.Println("save to DB", secondLandmark)

	if err != nil {
		fmt.Errorf("error creating first epoch, %w", err)
	}
	fmt.Println(secondTree)

	// Generate proof for LM1
	//certToCheck := []byte("issued-id-002")

	// Doesnt work for some reason // still has bug
	issuedProof, err := firstLandmark.newLandmarkProof(issuedCerts2[1])
	if err != nil {
		fmt.Errorf("creating proof for issued 002 %w", err)
	}
	revokedProof, err := firstLandmark.newLandmarkProof(issuedCerts2[0])
	if err != nil {
		fmt.Errorf("creating proof for issued 002 %w", err)
	}

	fmt.Println(issuedProof)
	fmt.Println(revokedProof)
	responseRevoked, err := NewMerkleResponse(issuedCerts2[0], secondLandmark)
	responseGood, err := NewMerkleResponse(issuedCerts2[1], secondLandmark)

	fmt.Println(responseRevoked, responseGood)
	// TODO: Validate the landmark proof
	fmt.Println()

}
