package main

import (
	"fmt"
	"time"
)

const (
	Good    = 0
	Revoked = 1
	Unknown = 2
)

type MerkleResponse struct {
	status    int8
	timestamp time.Time
	proof     *CombinedProof
}

// TODO: ---PLACEHOLDER---
// TODO: actually search and find the root
func findTreeTMP(rHash []byte) (*CombinedTree, error) {
	// tmp
	dBlocks, err := GenerateRandBlocks(10)
	if err != nil {
		return &CombinedTree{nil, time.Now(), nil, nil}, err
	}
	cTree, err := NewCombinedTree(dBlocks)
	// tmp
	if err != nil {
		return &CombinedTree{nil, time.Now(), nil, nil}, err
	}
	return cTree, nil
}

// What is included in the response?
// TODO: Temp implementation, rootHash shall be given as part of the arguments
func NewOCSPResponse(certHash []byte, rootHash []byte, c *CombinedTree) (*MerkleResponse, error) {
	var status int8
	var proof *CombinedProof
	// If we have the root (for testing / tmp implementation)
	if c != nil {
		status, _ = getStatus(c, certHash)
		proof, _ = c.newTreeProof(certHash)
		fmt.Println("CombinedTree not nil, testing NewOCSPResponse")
		return &MerkleResponse{status, time.Now(), proof}, nil
	}
	//  else Find the matching root-hash from db or smth... (actual use, use rootHASH given in args)
	tree, _ := findTreeTMP(certHash)
	status, _ = getStatus(tree, certHash)
	proof, _ = tree.newTreeProof(certHash)

	return &MerkleResponse{status, time.Now(), proof}, nil
}
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
