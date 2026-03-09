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
	curTree    *CombinedTree
	lastTree   *CombinedTree
	hashAlgo   crypto.Hash
	date       time.Time
}

// NewLandmark takes two combined tree trees (Last Epoch and current Epoch), hashes the two roots, and signs them.
func NewLandmark(tCur *CombinedTree, tLast *CombinedTree, h crypto.Hash, key *rsa.PrivateKey) (*Landmark, error) {
	hFunc := h.HashFunc().New()
	hFunc.Write(tCur.root)
	hFunc.Write(tLast.root)

	signed, err := key.Sign(nil, hFunc.Sum(nil), h)

	if err != nil {
		return &Landmark{nil, nil, nil, h, time.Now()}, err
	}
	return &Landmark{signed, tCur, tLast, h, time.Now()}, nil
}

// newLandmarkProof generates a CombinedProof and landmarkProof used to prove the membership or non membership (TODO:Landmark proof)
func (l *Landmark) newLandmarkProof() {

}

func (l *Landmark) getDate() string {
	return l.date.String()
}
