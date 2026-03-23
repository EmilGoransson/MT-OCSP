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
	Date     time.Time
	Log      *tree.Log
	LogIndex uint64
	Ctree    *tree.Combined
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
// NewLandmark commits a combinedTree to the Log.
func NewLandmark(l *tree.Log, c *tree.Combined) (*Landmark, error) {
	// Commit curTree and data to the Log (can include timestamp if needed)
	err := l.AppendToLog(c.Root)
	if err != nil {
		return nil, fmt.Errorf("adding combinedTree to Log, %v", err)
	}
	index := l.Size() - 1
	return &Landmark{
		Log:      l,
		LogIndex: index,
		Ctree:    c,
		Date:     time.Now(),
	}, nil
}

// NewSignedHead hashes together data and signs the hash
func (l *Landmark) NewSignedHead(k *rsa.PrivateKey, h crypto.Hash) (*SignedLandmark, error) {
	// Signs the hash of (RootHash + TreeSize + Date
	hasher := h.New()
	rootHash, err := l.Log.RootHash()
	if err != nil {
		return nil, fmt.Errorf("getting root hash, %v", err)
	}
	// Converts treesize to []byte
	treeSizeHash := make([]byte, 8)
	size := l.Log.Size()
	binary.BigEndian.PutUint64(treeSizeHash, size)
	timeHash, err := l.Date.MarshalBinary()
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
		Date:           l.Date,
	}, nil

}

// newLandmarkProof generates a LandmarkProof used to prove the membership or non membership
func (l *Landmark) NewLandmarkProof(hash []byte) (*LandmarkProof, error) {
	// Generate combinedTree Proof
	if l.Ctree.RevSMT.SparseMerkleTree == nil {
		return nil, fmt.Errorf("empty revocation, froze before generating proof")
	}
	status, err := getStatus(l.Ctree, hash)
	var issuedProof *merkletree.Proof
	var rProof smt.SparseMerkleProof
	var cProof *CombinedProof
	if status == Unknown {
		issuedProof, err := l.Ctree.NewNonMembershipProof(hash)
		if err != nil {
			return nil, fmt.Errorf("creating newNonMembership proof %v, ", err)
		}
		cProof = &CombinedProof{
			IssueProof: issuedProof,
			RevProof:   nil,
		}
	}

	issuedProof, err = l.Ctree.NewMembershipProofIssued(hash)
	if err != nil {
		return nil, fmt.Errorf("fetching membershipProof, %v", err)
	}
	rProof, err = l.Ctree.NewMembershipProofRevoked(hash)
	cProof = &CombinedProof{
		IssueRoot:  l.Ctree.IssuedMT.Root,
		RevRoot:    l.Ctree.RevSMT.Root(),
		IssueProof: issuedProof,
		RevProof:   &rProof,
	}

	if err != nil {
		return &LandmarkProof{nil, 0, nil}, err
	}
	// Generate Append Log proof
	// Find hash id
	logProof, err := l.Log.NewProof(l.LogIndex)

	return &LandmarkProof{
		logProof:      logProof,
		logIndex:      l.LogIndex,
		CombinedProof: cProof,
	}, nil
}
