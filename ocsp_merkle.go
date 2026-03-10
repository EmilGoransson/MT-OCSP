package main

import (
	"time"
)

const (
	Good    = 0
	Revoked = 1
	Unknown = 2
)

// TODO: Should actully contain the landmark proof
type MerkleResponse struct {
	status    int8
	timestamp time.Time
	proof     *LandmarkProof
}

// TODO: ---PLACEHOLDER---
// TODO: actually search and find the root
func findTreeTMP(rHash []byte) (*CombinedTree, error) {
	// tmp
	dBlocks, err := GenerateRandBlocks(10)
	if err != nil {
		return &CombinedTree{nil, time.Now(), nil, nil}, err
	}
	cTree, err := NewCombinedTree(dBlocks, nil)
	// tmp
	if err != nil {
		return &CombinedTree{nil, time.Now(), nil, nil}, err
	}
	return cTree, nil
}

// What is included in the response?
// TODO: Temp implementation, rootHash shall be given as part of the arguments
func NewMerkleResponse(certHash []byte, l *Landmark) (*MerkleResponse, error) {
	var status int8

	/*
	   // If we have the root (for testing / tmp implementation)
	   	if l.curTree != nil {
	   		proof, _ := l.curTree.newTreeProof(certHash)
	   		status, _ = getStatus(l.curTree, certHash)
	   		p := &LandmarkProof{prevUnsignedHashHead: l.lastLandmark.head, combinedProof: proof}

	   		fmt.Println("CombinedTree not nil, testing NewMerkleResponse")
	   		return &MerkleResponse{status, time.Now(), p}, nil
	   	}
	*/
	//  else Find the matching root-hash from db or smth... (actual use, use rootHASH given in args)
	//tree, _ := findTreeTMP(certHash)
	// why 2?

	status, _ = getStatus(l.curTree, certHash)
	proof, _ := l.curTree.newTreeProof(certHash)
	p := &LandmarkProof{prevUnsignedHashHead: l.lastLandmark.head, combinedProof: proof}
	return &MerkleResponse{status, time.Now(), p}, nil
}

// getStatus finds the status of a certificate from a *combinedTree, and returns Good = 0, Revoked = 1 or Unknown = 2
func getStatus(cTree *CombinedTree, hash []byte) (int8, error) {
	isRevoked, err := cTree.revSMT.Has(hash)
	if err != nil {
		return -1, err
	}
	isIssued, err := cTree.has(hash)
	if err != nil {
		return -1, err
	}
	if !isIssued {
		return Unknown, nil
	}
	if !isRevoked {
		return Good, nil
	}
	return Revoked, nil
}

// Should validate proof be here or in combinedtree?
