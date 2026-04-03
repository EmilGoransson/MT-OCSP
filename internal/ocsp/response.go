package ocsp

import (
	"fmt"
	"merkle-ocsp/internal/tree"
	"time"
)

type Status int

const (
	Good = iota
	Revoked
	Unknown
)

type Response struct {
	Status    int8
	Timestamp time.Time
	Proof     *LandmarkProof
}
type Request struct {
	SerialBytes []byte
	Date        time.Time
}

func NewResponse(certHash []byte, l *Landmark, lNewest *Landmark) (*Response, error) {
	var status int8
	var err error
	var p *LandmarkProof
	if lNewest == nil {
		lNewest = l
	}
	if l == nil {
		return nil, fmt.Errorf("landmark is nil, date and cert not found")
	}
	status, err = getStatus(l.CTree, lNewest.CTree, certHash)
	if err != nil {
		return nil, err
	}
	p, err = l.NewLandmarkProof(certHash, lNewest)
	if err != nil {
		return nil, fmt.Errorf("generating proof for util, %v", err)
	}
	return &Response{status, time.Now(), p}, nil
}

// TODO: Should it return unknown if issueTree = nil? With date-based finding, it should simply check the tree for the hash
// getStatus finds the status of a certificate from an issue-tree and the latest rev-tree,
func getStatus(issueTree *tree.Combined, newestTree *tree.Combined, hash []byte) (int8, error) {
	if issueTree == nil {
		return Unknown, nil
	}
	isIssued, err := issueTree.Has(hash)
	if err != nil {
		return -1, err
	}
	if !isIssued {
		return Unknown, nil
	}
	isRevoked, err := newestTree.RevSMT.Has(hash)
	if err != nil {
		return -1, err
	}
	if !isRevoked {
		return Good, nil
	}
	return Revoked, nil
}
func (s Status) String() string {
	switch s {
	case Good:
		return "Good"
	case Revoked:
		return "Revoked"
	case Unknown:
		return "Unknown"
	default:
		return "bad status"
	}
}
