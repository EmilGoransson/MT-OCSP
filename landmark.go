package main

import (
	"crypto"
	"crypto/rsa"
	"time"
)

// TODO: How should i "scale" this? / Would this scale? -> SignedRoot is distributed, but CombinedTree is stored local by CA

// Should be PQ safe (not RSA)
type Landmark struct {
	signedHead   []byte
	head         []byte
	curTree      *CombinedTree
	lastLandmark *Landmark
	hashAlgo     crypto.Hash
	date         time.Time
}
type LandmarkProof struct {
	prevUnsignedHashHead []byte
	combinedProof        *CombinedProof
}

func NewEmptyLandmark(h crypto.Hash) *Landmark {
	return &Landmark{signedHead: nil, head: nil, curTree: nil, lastLandmark: nil, hashAlgo: h, date: time.Now()}
}

// TODO: use the same revocation tree as last epoch & remove it
// NewLandmark takes two combined tree trees (Last Epoch and current Epoch), hashes the two roots, and signs them.
func NewLandmark(landmarkLast *Landmark, tCur *CombinedTree, h crypto.Hash, key *rsa.PrivateKey) (*Landmark, error) {
	hFunc := h.HashFunc().New()
	hFunc.Write(tCur.root)
	hFunc.Write(landmarkLast.head)
	head := hFunc.Sum(nil)
	signed, err := key.Sign(nil, head, h)
	if err != nil {
		return &Landmark{nil, nil, nil, nil, h, time.Now()}, err
	}

	return &Landmark{signedHead: signed, head: head, curTree: tCur, lastLandmark: landmarkLast, hashAlgo: h, date: time.Now()}, nil
}

// newLandmarkProof generates a LandmarkProof used to prove the membership or non membership
func (l *Landmark) newLandmarkProof(b []byte) (*LandmarkProof, error) {
	proof, err := l.curTree.newTreeProof(b)
	if err != nil {
		return &LandmarkProof{nil, nil}, err
	}
	return &LandmarkProof{l.lastLandmark.head, proof}, nil
}

// NewLandmarkProofEntireEpoch Implements issue https://github.com/EmilGoransson/MT-OCSP/issues/6
// buildLandmarkProofChain returns a chain containing the required hashes to reconstruct the landmark-hash-chain from k to latest epoch
func (l *Landmark) buildLandmarkProofChain() {

}

func (l *Landmark) getDate() string {
	return l.date.String()
}
