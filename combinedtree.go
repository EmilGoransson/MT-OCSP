package main

import (
	"crypto/sha256"
	"time"

	"github.com/celestiaorg/smt"
	"github.com/txaty/go-merkletree"
)

// TODO: How should i "scale" this? / Would this scale? -> SignedRoot is distributed, but CombinedTree is stored local by CA
type CombinedTree struct {
	root     []byte
	date     time.Time
	issuedMT *merkletree.MerkleTree
	revSMT   *smt.SparseMerkleTree
}

// What is good practice here?
// take head and sign using some key
// Add to tree from list?
// Random blocks in merkle tree
// TODO: Figure out how to do with "input" blocks.
// TODO: Perhaps create function that takes input blocks for MT and input blocks for SMT & adds them to tree?
func NewCombinedTree(merkleBlocks []merkletree.DataBlock) (*CombinedTree, error) {
	// To be changed
	merkle, err := NewMerkle(merkleBlocks)
	if err != nil {
		return nil, err
	}

	tree := CombinedTree{
		root:     nil,
		issuedMT: merkle,
		revSMT:   NewSparseMerkle(),
	}
	return &tree, nil
}

// TODO: Figure out if I should store the hash vs if i should not
func (c *CombinedTree) addRevocationToTree(value []byte) ([]byte, error) {
	newRoot, err := c.revSMT.Update(value, value)
	if err != nil {
		return nil, err
	}
	c.updateGlobalRoot()
	return newRoot, nil
}
func (c *CombinedTree) addBulkRevocationToTree(values [][]byte) ([]byte, error) {
	var newRoot []byte
	var err error
	for _, value := range values {
		newRoot, err = c.revSMT.Update(value, value)
		if err != nil {
			return nil, err
		}
	}
	c.updateGlobalRoot()
	return newRoot, nil
}

func (c *CombinedTree) getMembershipProof(value []byte) (smt.SparseMerkleProof, error) {
	proof, err := c.revSMT.Prove(value)
	if err != nil {
		return smt.SparseMerkleProof{}, err
	}
	return proof, nil
}
func (c *CombinedTree) validateSparseMTMembershipProof(proof smt.SparseMerkleProof, value []byte) (bool, error) {
	return smt.VerifyProof(proof, c.revSMT.Root(), value, value, sha256.New()), nil
}

// validateSparseMTNonMembershipProof expects the value to be empty if it's a Non membership proof
func (c *CombinedTree) validateSparseMTNonMembershipProof(proof smt.SparseMerkleProof, value []byte) (bool, error) {
	return smt.VerifyProof(proof, c.revSMT.Root(), value, []byte{}, sha256.New()), nil
}

// Is this really possible?
func (c *CombinedTree) addIssuanceToTree() {

	c.updateGlobalRoot()
}
func (c *CombinedTree) updateGlobalRoot() {
	h := sha256.New()
	h.Write(c.issuedMT.Root)
	h.Write(c.revSMT.Root())
	c.root = h.Sum(nil)
}
