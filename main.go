package main

import (
	"crypto"
	"fmt"
)

func main() {

	// -- Build a landmark chain --
	// Generate a CA-keypair (currently RSA, TBC)
	keyPair, err := NewKeyPair(2048)

	// Start head (empty tree) & actual tree
	initEpoch := NewStartTree()

	// Hour 0 to 1: collect issued and revoked certificates (can use NewCertificate)
	issuedCerts := [][]byte{
		[]byte("issued-id-001"),
		[]byte("issued-id-002"),
		[]byte("issued-id-003"),
		[]byte("issued-id-004"),
	}
	var revokedCerts [][]byte
	for i, b := range issuedCerts {
		if i%2 == 0 {
			revokedCerts = append(revokedCerts, b)
		}
	}
	// Hour: 0-1, create a tree for the issued certs TODO: add so that the certs are signed using the CA-key
	// TODO: add so that u can add revoked certs at the same time as issued certs
	firstEpoch, err := NewCombinedTree(issuedCerts)
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
	// Hour: 1-2, Create a tree for the issued certs
	secondEpoch, _ := NewCombinedTree(issuedCerts2)
	// Hour: 1-2, add the revoked certs
	_, _ = secondEpoch.addBulkRevocationToTree(revokedCerts2)
	// Create second landmark
	secondLandmark, err := NewLandmark(firstEpoch, secondEpoch, crypto.SHA256, keyPair)

	fmt.Println("save to DB", secondLandmark)

	// TODO: Save landmark to DB or smht
	if err != nil {
		fmt.Errorf("error creating first epoch, %w", err)
	}

}
