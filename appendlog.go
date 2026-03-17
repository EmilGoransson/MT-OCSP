package main

import (
	"bytes"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

type AppendLog struct {
	treeRange *compact.Range            // Stores the "peeks" / Calculated root
	nodeStore map[compact.NodeID][]byte // Stores the leaf and intermediate nodes
}

func NewAppendLog() (*AppendLog, error) {
	factory := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	return &AppendLog{
		treeRange: factory.NewEmptyRange(0),
		nodeStore: make(map[compact.NodeID][]byte),
	}, nil
}

func (a *AppendLog) appendToLog(item []byte) error {
	// Defines "visitor" function used to save the item to the nodeStore
	saveNode := func(id compact.NodeID, hash []byte) {
		a.nodeStore[id] = hash
	}
	// Hashes item before adding it
	hash := rfc6962.DefaultHasher.HashLeaf(item)
	if err := a.treeRange.Append(hash, saveNode); err != nil {
		return fmt.Errorf("adding data to append-log, %v", err)
	}
	return nil
}
func (a *AppendLog) getSize() (ret uint64) {
	return a.treeRange.End()
}

// newProof generates the proof needed to prove for index from nodeStore
func (a *AppendLog) newProof(index uint64) ([][]byte, error) {
	// Build the blueprint
	blueprint, err := proof.Inclusion(index, a.getSize())
	if err != nil {
		return nil, fmt.Errorf("creating blueprint for proof, %v", err)
	}
	// Create proof from blueprint
	var hashes [][]byte

	for _, id := range blueprint.IDs {
		hash, inMap := a.nodeStore[id]
		if !inMap {
			return nil, fmt.Errorf("value missing from nodeStore")
		}
		hashes = append(hashes, hash)
	}

	hashProof, err := blueprint.Rehash(hashes, rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		return nil, fmt.Errorf("error creating proof from blueprint, %v", err)
	}
	return hashProof, nil
}

// VerifyProof for (testing), should use proof.VerifyInclusion if you have the index directly for fast proof gen
func (a *AppendLog) VerifyProof(hash []byte, hashProof [][]byte) (bool, error) {
	// Find id from hash
	var index uint64
	var found bool

	for node, storedHash := range a.nodeStore {
		if node.Level == 0 && bytes.Equal(hash, storedHash) {
			index = node.Index
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("leaf-hash not found in nodeMap")
	}
	rootHash, err := a.treeRange.GetRootHash(nil)
	if err != nil {
		return false, fmt.Errorf("calculating root-hash, %v", err)
	}
	err = proof.VerifyInclusion(rfc6962.DefaultHasher, index, a.getSize(), hash, hashProof, rootHash)
	return err == nil, err
}
