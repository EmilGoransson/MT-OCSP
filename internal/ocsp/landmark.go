package ocsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"merkle-ocsp/internal/tree"
	"time"

	"github.com/celestiaorg/smt"
	"github.com/txaty/go-merkletree"
)

// TODO: How should i "scale" this? / Would this scale? -> SignedRoot is distributed, but Combined is stored local by CA

// Should be PQ safe (not RSA)
type Landmark struct {
	date     time.Time
	log      *tree.Log
	logIndex uint64
	cTree    *tree.Combined
}

// SignedLandmark is distributed out of band
type SignedLandmark struct {
	SignedHashData []byte
	LogRoot        []byte
	LogSize        uint64
	Date           time.Time
}

type LandmarkProof struct {
	logProof      [][]byte
	logIndex      uint64
	CombinedProof *CombinedProof
}

type CombinedProof struct {
	IssueRoot  []byte // Placeholder / temp fix
	RevRoot    []byte // Placeholder / temp fix
	IssueProof *merkletree.Proof
	RevProof   *smt.SparseMerkleProof
}

// TODO: use the same revocation tree as last epoch & remove it
// NewLandmark commits a combinedTree to the log.
func NewLandmark(l *tree.Log, c *tree.Combined) (*Landmark, error) {
	// Commit curTree and data to the log (can include timestamp if needed)
	err := l.AppendToLog(c.Root)
	if err != nil {
		return nil, fmt.Errorf("adding combinedTree to log, %v", err)
	}
	index := l.Size() - 1
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
	size := l.log.Size()
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
		SignedHashData: signedHash,
		LogRoot:        rootHash,
		LogSize:        size,
		Date:           l.date,
	}, nil

}

// newLandmarkProof generates a LandmarkProof used to prove the membership or non membership
func (l *Landmark) NewLandmarkProof(hash []byte) (*LandmarkProof, error) {
	// Generate combinedTree Proof
	if l.cTree.RevSMT.SparseMerkleTree == nil {
		return nil, fmt.Errorf("empty revocation, froze before generating proof")
	}
	status, err := getStatus(l.cTree, hash)
	var issuedProof *merkletree.Proof
	var rProof smt.SparseMerkleProof
	var cProof *CombinedProof
	if status == Unknown {
		issuedProof, err := l.cTree.NewNonMembershipProof(hash)
		if err != nil {
			return nil, fmt.Errorf("creating newNonMembership proof %v, ", err)
		}
		cProof = &CombinedProof{
			IssueProof: issuedProof,
			RevProof:   nil,
		}
	}

	issuedProof, err = l.cTree.NewMembershipProofIssued(hash)
	if err != nil {
		return nil, fmt.Errorf("fetching membershipProof, %v", err)
	}
	rProof, err = l.cTree.NewMembershipProofRevoked(hash)
	cProof = &CombinedProof{
		IssueRoot:  l.cTree.IssuedMT.Root,
		RevRoot:    l.cTree.RevSMT.Root(),
		IssueProof: issuedProof,
		RevProof:   &rProof,
	}

	if err != nil {
		return &LandmarkProof{nil, 0, nil}, err
	}
	// Generate Append log proof
	// Find hash id
	logProof, err := l.log.NewProof(l.logIndex)

	return &LandmarkProof{
		logProof:      logProof,
		logIndex:      l.logIndex,
		CombinedProof: cProof,
	}, nil
}
