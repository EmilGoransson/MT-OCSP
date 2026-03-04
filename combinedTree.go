package main

import (
	"github.com/celestiaorg/smt"
	"github.com/txaty/go-merkletree"
)

type combinedTree struct {
	head     []byte
	issuedMT merkletree.MerkleTree
	revSMT   smt.SparseMerkleTree
}

// What is good practice here?
// take head and sign using some key
// Add to tree from list?
func (c *combinedTree) getCombinedTree() *combinedTree {
	return c
}
func createNewCombinedTree() *combinedTree {
	// Create a SMT
	// Create MT
	tree := combinedTree{
		head:     nil,
		issuedMT: *createEmptyMT(),
		revSMT:   *createEmptySMT(),
	}
	return &tree
}
func (c *combinedTree) addRevocationToTree() {
}
func (c *combinedTree) addIssuenceToTree() {

}
