package main

import (
	"fmt"
)

func main() {
	var revokedCerts [][]byte

	// Create a CA that has a self-signed root cert + private key
	caCert, err := NewRootCertificateAndKey()
	if err != nil {
		panic(err)
	}
	fmt.Println(caCert)

	// Generate a list of certificates signed by the CA.
	cList, err := NewListRandomCertificates()
	fmt.Println(cList)

	// Add them to the issued side
	tree, err := NewCombinedTree(cList)

	if err != nil {
		panic(err)
	}

	fmt.Println(tree)
	// Revoke some of them
	for i, b := range cList {
		if i%3 == 0 {
			revokedCerts = append(revokedCerts, b)
		}
	}

	for _, rBytes := range revokedCerts {
		_, err := tree.addRevocationToTree(rBytes)
		if err != nil {
			return
		}
	}
	fmt.Println(tree)

	// Try and generate proof for one if the certificates
	mProof, err := tree.newMembershipProofIssued(cList[3])
	if err != nil {
		panic(err)
	}
	fmt.Println(mProof)

}
