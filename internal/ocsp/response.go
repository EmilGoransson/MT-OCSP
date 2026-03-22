package ocsp

import (
	"fmt"
	"merkle-ocsp/internal/tree"
	"time"
)

const (
	Good = iota
	Revoked
	Unknown
)

// TODO: Should actully contain the landmark proof
type Response struct {
	Status    int8
	timestamp time.Time
	Proof     *LandmarkProof
}

// TODO: ---PLACEHOLDER---
// TODO: actually search and find the root
func findTreeTMP(rHash []byte) (*tree.Combined, error) {
	return nil, nil
}

// What is included in the response?
// TODO: Temp implementation, rootHash shall be given as part of the arguments
func NewResponse(certHash []byte, l *Landmark) (*Response, error) {
	var status int8
	status, _ = getStatus(l.cTree, certHash)
	p, err := l.NewLandmarkProof(certHash)
	if err != nil {
		return nil, fmt.Errorf("generating proof for cert, %v", err)
	}
	return &Response{status, time.Now(), p}, nil
}

// getStatus finds the status of a certificate from a *combinedTree, and returns Good = 0, Revoked = 1 or Unknown = 2
func getStatus(cTree *tree.Combined, hash []byte) (int8, error) {
	isRevoked, err := cTree.RevSMT.Has(hash)
	if err != nil {
		return -1, err
	}
	isIssued, err := cTree.Has(hash)
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
