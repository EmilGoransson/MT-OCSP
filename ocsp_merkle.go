package main

import (
	"fmt"
	"time"
)

const (
	Good = iota
	Revoked
	Unknown
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
		return &CombinedTree{root: nil, date: time.Now(), issuedMT: nil}, err
	}
	cTree, err := NewCombinedTree(dBlocks, nil, nil)
	// tmp
	if err != nil {
		return &CombinedTree{root: nil, date: time.Now(), issuedMT: nil}, err
	}
	return cTree, nil
}

// What is included in the response?
// TODO: Temp implementation, rootHash shall be given as part of the arguments
func NewMerkleResponse(certHash []byte, l *Landmark) (*MerkleResponse, error) {
	var status int8
	status, _ = getStatus(l.cTree, certHash)
	p, err := l.NewLandmarkProof(certHash)
	if err != nil {
		return nil, fmt.Errorf("generating proof for cert, %v", err)
	}
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
