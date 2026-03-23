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
	CTree    *tree.Combined
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
	IssueRoot     []byte // Placeholder / temp fix
	RevRoot       []byte // Placeholder / temp fix
	IssueProof    *merkletree.Proof
	NonIssueProof *tree.ExclusionProofSorted
	RevProof      *smt.SparseMerkleProof
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
		CTree:    c,
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
	if l.CTree.RevSMT.SparseMerkleTree == nil {
		return nil, fmt.Errorf("empty revocation, froze before generating proof")
	}
	status, err := getStatus(l.CTree, hash)
	if err != nil {
		return nil, err
	}
	var issuedProof *merkletree.Proof
	var rProof smt.SparseMerkleProof
	var cProof *CombinedProof

	// Make into its own type of proof maybe since you need NewNonMembershipProof for EVERY tree in EVERY epoch, Only needs to be one if its Date based
	if status == Unknown {
		issuedProof, err := l.CTree.NewNonMembershipProof(hash)
		if err != nil {
			return nil, fmt.Errorf("creating newNonMembership proof %v, ", err)
		}
		cProof = &CombinedProof{
			IssueRoot:     l.CTree.IssuedMT.Root,
			IssueProof:    nil,
			NonIssueProof: issuedProof,
			RevProof:      nil,
		}
	} else {
		issuedProof, err = l.CTree.NewMembershipProofIssued(hash)
		if err != nil {
			return nil, fmt.Errorf("fetching membershipProof, %v", err)
		}
		rProof, err = l.CTree.NewMembershipProofRevoked(hash)
		cProof = &CombinedProof{
			IssueRoot:     l.CTree.IssuedMT.Root,
			RevRoot:       l.CTree.RevSMT.Root(),
			IssueProof:    issuedProof,
			RevProof:      &rProof,
			NonIssueProof: nil,
		}

		if err != nil {
			return &LandmarkProof{nil, 0, nil}, err
		}
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
