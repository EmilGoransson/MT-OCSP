package ocsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	Frequency      time.Duration
	Date           time.Time
}

type LandmarkProof struct {
	LogProof       [][]byte
	LogIndex       uint64
	NewestLogProof [][]byte
	NewestLogIndex uint64 // Index of the newest landmark in the log
	CombinedProof  *CombinedProof
}

type CombinedProof struct {
	IssueRoot     []byte // Placeholder / temp fix
	RevRoot       []byte // Placeholder / temp fix
	IssueProof    *merkletree.Proof
	IssueDate     time.Time
	IssueEpochRev []byte
	NonIssueProof *tree.ExclusionProofSorted
	RevProof      *smt.SparseMerkleProof
	RevEpochIssue []byte
}

// TODO: use the same revocation tree as last epoch & remove it
// NewLandmark commits a combinedTree to the Log.
func NewLandmark(l *tree.Log, c *tree.Combined) (*Landmark, error) {
	// Commit curTree and data to the Log (can include Timestamp if needed)
	date := c.Date

	bDate, err := date.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling date, err: %v", err)
	}
	h := sha256.New()
	h.Write(c.Root)
	h.Write(bDate)
	err = l.AppendToLog(h.Sum(nil))
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
func (l *Landmark) NewSignedHead(k *rsa.PrivateKey, h crypto.Hash, f time.Duration) (*SignedLandmark, error) {
	// Signs the hash of (RootHash + TreeSize + Date
	if l == nil {
		return nil, fmt.Errorf("landmark is nil")
	}
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
	// Convert freq to bytes
	freqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(freqBytes, uint64(f))
	if err != nil {
		return nil, fmt.Errorf("marshaling time, %v", err)
	}

	// Write bytes and hash
	hasher.Write(rootHash)
	hasher.Write(treeSizeHash)
	hasher.Write(timeHash)
	hasher.Write(freqBytes)
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
		Frequency:      f,
	}, nil

}

// Rev is always in the latest landmark.
// So, we only need the issue-landmark. l is issue landmark in this case

// lNewest contains the rev-combined-tree always

// newLandmarkProof generates a LandmarkProof used to prove the membership or non membership
func (l *Landmark) NewLandmarkProof(hash []byte, lNewest *Landmark) (*LandmarkProof, error) {
	// Generate combinedTree Proof
	if l == nil {
		return nil, fmt.Errorf("landmark is nil")
	}
	if lNewest == nil {
		lNewest = l
	}
	//Fetches status a 2nd time, refactor?
	status, err := getStatus(l.CTree, lNewest.CTree, hash)
	if err != nil {
		return nil, err
	}
	var issuedProof *merkletree.Proof
	var rProof smt.SparseMerkleProof
	var cProof *CombinedProof

	// Make into its own type of proof maybe since you need NewNonMembershipProof for EVERY tree in EVERY epoch, Only needs to be one if its Date based
	if status == Unknown {
		proof, err := l.CTree.NewNonMembershipProof(hash)
		if err != nil {
			return nil, fmt.Errorf("creating newNonMembership proof %v, ", err)
		}
		cProof = &CombinedProof{
			IssueRoot:     l.CTree.IssuedMT.Root,
			IssueEpochRev: l.CTree.RevSMT.Root(),
			IssueDate:     l.CTree.Date,
			RevRoot:       lNewest.CTree.RevSMT.Root(),
			RevEpochIssue: lNewest.CTree.IssuedMT.Root,
			IssueProof:    nil,
			NonIssueProof: proof,
			RevProof:      nil,
		}
	} else {
		// IssueProof needs the rev-root of its "own" combined tree
		// RevProof needs the issue-root of its "own" combined tree
		if lNewest.CTree == nil || lNewest.CTree.RevSMT == nil || lNewest.CTree.RevSMT.SparseMerkleTree == nil {
			return nil, fmt.Errorf("revocation tree unavailable for latest epoch")
		}

		issuedProof, err = l.CTree.NewMembershipProofIssued(hash)
		if err != nil {
			return nil, fmt.Errorf("fetching membershipProof, %v", err)
		}
		rProof, err = lNewest.CTree.NewMembershipProofRevoked(hash)
		cProof = &CombinedProof{
			IssueRoot:     l.CTree.IssuedMT.Root,
			IssueEpochRev: l.CTree.RevSMT.Root(),
			IssueDate:     l.CTree.Date,
			RevRoot:       lNewest.CTree.RevSMT.Root(),
			RevEpochIssue: lNewest.CTree.IssuedMT.Root,
			IssueProof:    issuedProof,
			RevProof:      &rProof,
			NonIssueProof: nil,
		}

		if err != nil {
			return &LandmarkProof{
				LogProof:       nil,
				LogIndex:       0,
				NewestLogProof: nil,
				NewestLogIndex: 0,
				CombinedProof:  nil,
			}, err
		}
	}

	// Generate Append Log proof
	// Find hash id
	logProof, err := l.Log.NewProof(l.LogIndex)
	if err != nil {
		return nil, err
	}

	// Generate a log-inclusion proof for the newest landmark so that Verify can verify it against the log .
	newestLogProof := logProof
	newestLogIndex := l.LogIndex
	if lNewest.LogIndex != l.LogIndex {
		newestLogProof, err = lNewest.Log.NewProof(lNewest.LogIndex)
		if err != nil {
			return nil, fmt.Errorf("generating newest log proof, %v", err)
		}
		newestLogIndex = lNewest.LogIndex
	}

	return &LandmarkProof{
		LogProof:       logProof,
		LogIndex:       l.LogIndex,
		NewestLogProof: newestLogProof,
		NewestLogIndex: newestLogIndex,
		CombinedProof:  cProof,
	}, nil
}
