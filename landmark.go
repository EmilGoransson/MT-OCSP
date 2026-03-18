package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"time"
)

// TODO: How should i "scale" this? / Would this scale? -> SignedRoot is distributed, but CombinedTree is stored local by CA

// Should be PQ safe (not RSA)
type Landmark struct {
	date     time.Time
	log      *AppendLog
	logIndex uint64
	cTree    *CombinedTree
}

// SignedLandmark is distributed out of band
type SignedLandmark struct {
	signedHashData []byte
	logRoot        []byte
	logSize        uint64
	date           time.Time
}

type LandmarkProof struct {
	logProof      [][]byte
	logIndex      uint64
	combinedProof *CombinedProof
}

// TODO: use the same revocation tree as last epoch & remove it
// NewLandmark commits a combinedTree to the log.
func NewLandmark(l *AppendLog, c *CombinedTree) (*Landmark, error) {
	// Commit curTree and data to the log (can include timestamp if needed)
	err := l.appendToLog(c.root)
	if err != nil {
		return nil, fmt.Errorf("adding combinedTree to log, %v", err)
	}
	index := l.getSize() - 1
	return &Landmark{
		log:      l,
		logIndex: index,
		cTree:    c,
		date:     time.Now(),
	}, nil
}

// NewSignedHead hashes together data and signs the hash
func (l *Landmark) NewSignedHead(k *rsa.PrivateKey, h crypto.Hash) (*SignedLandmark, error) {
	// Signs the hash of (RootHash + TreeSize + Date
	hasher := h.New()
	rootHash, err := l.log.RootHash()
	if err != nil {
		return nil, fmt.Errorf("getting root hash, %v", err)
	}
	// Converts treesize to []byte
	treeSizeHash := make([]byte, 8)
	size := l.log.getSize()
	binary.BigEndian.PutUint64(treeSizeHash, size)
	timeHash, err := l.date.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling time, %v", err)
	}
	hasher.Write(rootHash)
	hasher.Write(treeSizeHash)
	hasher.Write(timeHash)
	hash := hasher.Sum(nil)
	signedHash, err := k.Sign(rand.Reader, hash, h)
	if err != nil {
		return nil, fmt.Errorf("signing data, %v", err)
	}
	// Verify it
	// err = rsa.VerifyPKCS1v15(&k.PublicKey, h, hash, signedHash)
	// mt.Println(err)

	return &SignedLandmark{
		signedHashData: signedHash,
		logRoot:        rootHash,
		logSize:        size,
		date:           l.date,
	}, nil

}

// newLandmarkProof generates a LandmarkProof used to prove the membership or non membership
func (l *Landmark) NewLandmarkProof(b []byte) (*LandmarkProof, error) {
	// Generate combinedTree Proof
	if l.cTree.revSMT.SparseMerkleTree == nil {
		return nil, fmt.Errorf("empty revocation, froze before generating proof")
	}
	status, err := getStatus(l.cTree, b)
	cProof, err := l.cTree.newTreeProof(b, status)
	if err != nil {
		return &LandmarkProof{nil, 0, nil}, err
	}
	// Generate Append log proof
	// Find hash id
	index, err := l.log.findIndex(b)
	logProof, err := l.log.newProof(index)

	return &LandmarkProof{
		logProof:      logProof,
		logIndex:      index,
		combinedProof: cProof,
	}, nil
}
