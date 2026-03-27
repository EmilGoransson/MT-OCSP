package tree

import (
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

type Log struct {
	TreeRange      *compact.Range            // Stores the "peeks" / Calculated root
	NodeStore      map[compact.NodeID][]byte // Stores the leaf and intermediate nodes
	LeafIndexStore map[string]uint64
}

func NewLog() (*Log, error) {
	factory := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	return &Log{
		TreeRange:      factory.NewEmptyRange(0),
		NodeStore:      make(map[compact.NodeID][]byte),
		LeafIndexStore: make(map[string]uint64),
	}, nil
}

// AppendToLog takes a Hashed value (rfc6962.DefaultHasher.HashLeaf(bytes)), and adds it to the log
func (a *Log) AppendToLog(hash []byte) error {
	// Defines "visitor" function used to save the item to the NodeStore
	//Hash := rfc6962.DefaultHasher.HashLeaf(item)
	saveNode := func(id compact.NodeID, hash []byte) {
		a.NodeStore[id] = hash
		if id.Level == 0 {
			a.LeafIndexStore[string(hash)] = id.Index
		}
	}
	// Hashes item before adding it
	if err := a.TreeRange.Append(hash, saveNode); err != nil {
		return fmt.Errorf("adding data to append-log, %v", err)
	}
	return nil
}
func (a *Log) Size() (ret uint64) {
	return a.TreeRange.End()
}

// index takes a hashed value and finds the leaf index its stored in
func (a *Log) index(hash []byte) (uint64, error) {
	// Find id from Hash
	var found bool
	//Hash := rfc6962.DefaultHasher.HashLeaf(item)
	index, found := a.LeafIndexStore[string(hash)]
	/*
		for node, storedHash := range a.NodeStore {
			if node.Level == 0 && bytes.Equal(Hash, storedHash) {
				index = node.Index
				found = true
				break
			}
		} */

	if !found {
		return 0, fmt.Errorf("Hash not found in nodeMap")
	}
	return index, nil
}

// newProofFromItem takes a Hash, finds the index for it, and generates a proof
func (a *Log) newProofFromItem(hash []byte) ([][]byte, error) {
	//Hash := rfc6962.DefaultHasher.HashLeaf(item)
	index, exists := a.LeafIndexStore[string(hash)]
	if !exists {
		return nil, fmt.Errorf("Hash not in leaf")
	}
	return a.NewProof(index)
}

// NewProof generates the proof needed to prove for index from NodeStore
func (a *Log) NewProof(index uint64) ([][]byte, error) {
	// Build the blueprint
	blueprint, err := proof.Inclusion(index, a.Size())
	if err != nil {
		return nil, fmt.Errorf("creating blueprint for proof, %v", err)
	}
	// Create proof from blueprint
	var hashes [][]byte

	for _, id := range blueprint.IDs {
		hash, inMap := a.NodeStore[id]
		if !inMap {
			return nil, fmt.Errorf("value missing from NodeStore")
		}
		hashes = append(hashes, hash)
	}

	hashProof, err := blueprint.Rehash(hashes, rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		return nil, fmt.Errorf("error creating proof from blueprint, %v", err)
	}
	return hashProof, nil
}

// VerifyProof takes a Hash, for (testing), should use proof.VerifyInclusion if you have the index directly for fast proof gen
func (a *Log) VerifyProof(hash []byte, hashProof [][]byte) (bool, error) {
	// Find id from Hash

	index, err := a.index(hash)
	if err != nil {
		return false, err
	}
	rootHash, err := a.TreeRange.GetRootHash(nil)
	if err != nil {
		return false, fmt.Errorf("calculating root-Hash, %v", err)
	}
	err = proof.VerifyInclusion(rfc6962.DefaultHasher, index, a.Size(), hash, hashProof, rootHash)
	return err == nil, err
}
func (a *Log) RootHash() ([]byte, error) {
	return a.TreeRange.GetRootHash(nil)
}
