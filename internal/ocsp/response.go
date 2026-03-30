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
	Timestamp time.Time
	Proof     *LandmarkProof
}

// TODO: ---PLACEHOLDER---
// TODO:
func findTreeTMP(rHash []byte) (*tree.Combined, error) {
	return nil, nil
}

// What is included in the response?
// TODO: Handle unknown case- is currnetly skipped. Might need its own function
func NewResponse(certHash []byte, l *Landmark, lNewest *Landmark) (*Response, error) {
	var status int8
	var err error
	var p *LandmarkProof
	if l == nil {
		status = Unknown
	} else {
		status, err = getStatus(l.CTree, certHash)
		if err != nil {
			return nil, err
		}
		p, err = l.NewLandmarkProof(certHash, lNewest)
		if err != nil {
			return nil, fmt.Errorf("generating proof for util, %v", err)
		}
	}
	return &Response{status, time.Now(), p}, nil
}

// getStatus finds the status of a certificate from a *combinedTree, and returns Good = 0, Revoked = 1 or Unknown = 2
func getStatus(cTree *tree.Combined, hash []byte) (int8, error) {
	if cTree == nil {
		return Unknown, nil
	}
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
