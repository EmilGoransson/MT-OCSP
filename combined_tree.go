package main

import (
	"fmt"

	"github.com/celestiaorg/smt"
	"github.com/txaty/go-merkletree"
)

// CombinedTree exported
type CombinedTree struct {
	signedRoot []byte
	issuedMT   *merkletree.MerkleTree
	revSMT     *smt.SparseMerkleTree
}

// What is good practice here?
// take head and sign using some key
// Add to tree from list?

func NewCombinedTree() (*CombinedTree, error) {
	// Create a SMT
	// Create MT
	merkle, err := NewMerkle()
	if err != nil {
		return nil, fmt.Errorf("creating combined Merkle tree: %w", err)
	}

	tree := CombinedTree{
		signedRoot: nil,
		issuedMT:   merkle,
		revSMT:     NewSparseMerkle(),
	}
	return &tree, nil
}
func (c *CombinedTree) addRevocationToTree() {
}
func (c *CombinedTree) addIssuanceToTree() {

}
