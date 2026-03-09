package main

import (
	"crypto"
	"crypto/rsa"
	"time"
)

// TODO: How should i "scale" this? / Would this scale? -> SignedRoot is distributed, but CombinedTree is stored local by CA

// Should be PQ safe (not RSA)
type Landmark struct {
	signedHead []byte
	head       []byte
	curTree    *CombinedTree
	lastTree   *CombinedTree
	hashAlgo   crypto.Hash
	date       time.Time
}
type landmarkProof struct {
	prevUnsignedHashHead []byte
	combinedProof        *CombinedProof
}

// NewLandmark takes two combined tree trees (Last Epoch and current Epoch), hashes the two roots, and signs them.
func NewLandmark(tLast *CombinedTree, tCur *CombinedTree, h crypto.Hash, key *rsa.PrivateKey) (*Landmark, error) {
	hFunc := h.HashFunc().New()
	hFunc.Write(tCur.root)
	hFunc.Write(tLast.root)
	head := hFunc.Sum(nil)
	signed, err := key.Sign(nil, head, h)

	if err != nil {
		return &Landmark{nil, nil, nil, nil, h, time.Now()}, err
	}
	return &Landmark{signedHead: signed, head: head, curTree: tCur, lastTree: tLast, hashAlgo: h, date: time.Now()}, nil
}

// newLandmarkProof generates a CombinedProof and landmarkProof used to prove the membership or non membership
func (l *Landmark) newLandmarkProof(b []byte) (*landmarkProof, error) {
	proof, err := l.curTree.newTreeProof(b)
	if err != nil {
		return &landmarkProof{nil, nil}, err
	}
	return &landmarkProof{l.lastTree.root, proof}, nil
}

func (l *Landmark) getDate() string {
	return l.date.String()
}
