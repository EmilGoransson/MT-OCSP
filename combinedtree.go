package main

import (
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

	merkle, err := NewMerkle()
	if err != nil {
		return nil, err
	}

	tree := CombinedTree{
		signedRoot: nil,
		issuedMT:   merkle,
		revSMT:     NewSparseMerkle(),
	}
	return &tree, nil
}
func (c *CombinedTree) addRevocationToTree(value []byte) ([]byte, error) {
	newRoot, err := c.revSMT.Update(value, value)
	if err != nil {
		return nil, err
	}
	return newRoot, nil
}
func (c *CombinedTree) addBulkRevocationToTree(values [][]byte) ([]byte, error) {
	var newRoot []byte
	var err error
	for _, value := range values {
		newRoot, err = c.addRevocationToTree(value)
		if err != nil {
			return nil, err
		}
	}
	return newRoot, nil
}

func (c *CombinedTree) addIssuanceToTree() {

}
