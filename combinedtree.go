package main

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/celestiaorg/smt"
	"github.com/txaty/go-merkletree"
)

type CombinedTree struct {
	root     []byte
	date     time.Time
	issuedMT *SortedMerkleTree
	revSMT   *SparseMerkleTree
}
type CombinedProof struct {
	issueRoot  []byte // Placeholder / temp fix
	revRoot    []byte // Placeholder / temp fix
	issueProof *merkletree.Proof
	revProof   *smt.SparseMerkleProof
}

func NewEmptyTree() *CombinedTree {
	return &CombinedTree{root: nil, date: time.Now(), issuedMT: nil, revSMT: nil}
}

// TODO: Perhaps create function that takes input blocks for MT and input blocks for SparseMerkleTree & adds them to tree?
func NewCombinedTree(issuedCerts [][]byte, revokedCerts [][]byte, rTree *SparseMerkleTree) (*CombinedTree, error) {
	if rTree == nil {
		return nil, fmt.Errorf("the revcation tree must be non nil")
	}
	var newSMT *SparseMerkleTree
	merkle, err := NewMerkle(issuedCerts)
	if err != nil {
		return nil, err
	}
	// If there is a previous SMT, we want to build on top of that
	if rTree != nil {
		newSMT = rTree
	} else {
		newSMT = NewSparseMerkle()
	}
	tree := &CombinedTree{
		root:     nil,
		issuedMT: merkle,
		revSMT:   newSMT,
	}
	_, err = tree.addBulkRevocationToTree(revokedCerts)

	if err != nil {
		return nil, err
	}

	tree.updateGlobalRoot()
	return tree, nil
}

func (c *CombinedTree) addRevocationToTree(hash []byte) ([]byte, error) {
	newRoot, err := c.revSMT.Update(hash, hash)
	if err != nil {
		return nil, err
	}
	c.updateGlobalRoot()
	return newRoot, nil
}

// addBulkRevocationToTree takes list of hashes and adds it to the tree
func (c *CombinedTree) addBulkRevocationToTree(hashes [][]byte) ([]byte, error) {
	var newRoot []byte
	for _, hash := range hashes {
		in, err := c.revSMT.Has(hash)
		if in {
			fmt.Println("overwriting existing hash-value")
		}
		newRoot, err = c.revSMT.Update(hash, hash)
		if err != nil {
			return nil, err
		}
	}
	c.updateGlobalRoot()
	return newRoot, nil
}

func (c *CombinedTree) newMembershipProofRevoked(hash []byte) (smt.SparseMerkleProof, error) {
	return c.revSMT.Prove(hash)
}
func (c *CombinedTree) validateSparseMTMembershipProof(proof smt.SparseMerkleProof, value []byte) (bool, error) {
	return smt.VerifyProof(proof, c.revSMT.Root(), value, value, sha256.New()), nil
}

// validateSparseMTNonMembershipProof expects the value to be empty if it's a Non membership proof
func (c *CombinedTree) validateSparseMTNonMembershipProof(proof smt.SparseMerkleProof, value []byte) (bool, error) {
	return smt.VerifyProof(proof, c.revSMT.Root(), value, []byte{}, sha256.New()), nil
}
func (c *CombinedTree) validateSortedMTMembershipProof(b []byte, proof *merkletree.Proof) (bool, error) {
	dataBlock, err := ByteToDataBlock(b)

	if err != nil {
		return false, err
	}

	isValid, err := c.issuedMT.Verify(dataBlock, proof)
	if err != nil {
		return false, err
	}
	return isValid, nil
}

// newMembershipProofIssued takes a hash, converts it into a data block, and returns proof
func (c *CombinedTree) newMembershipProofIssued(hash []byte) (*merkletree.Proof, error) {

	dataBlock, err := ByteToDataBlock(hash)
	if err != nil {
		return nil, err
	}

	return c.issuedMT.Proof(dataBlock)
}

// hash takes a hash and returns a bool indicating if the tree has the value or not
func (c *CombinedTree) has(hash []byte) (bool, error) {

	return c.issuedMT.has(hash)
}

// TODO: Implement non membership proof in mt.merkletree
func (c *CombinedTree) newNonMembershipProof(hash []byte) (*merkletree.Proof, error) {
	_, err := ByteToDataBlock(hash)

	if err != nil {
		return nil, err
	}
	return &merkletree.Proof{}, err
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
func (c *CombinedTree) newTreeProof(hash []byte, status int8) (*CombinedProof, error) {
	// Check if in tree
	// Get issue proof
	// Get rev proof
	var issuedProof *merkletree.Proof
	var rProof smt.SparseMerkleProof
	if status == Unknown {
		// do smth
		issuedProof, err := c.newNonMembershipProof(hash)
		if err != nil {
			return nil, fmt.Errorf("creating newNonMembership proof %v, ", err)
		}
		return &CombinedProof{
			issueProof: issuedProof,
			revProof:   nil,
		}, nil
	}
	issuedProof, err := c.newMembershipProofIssued(hash)
	if err != nil {
		return nil, fmt.Errorf("fetching membershipProof, %v", err)
	}
	rProof, err = c.newMembershipProofRevoked(hash)
	return &CombinedProof{
		issueRoot:  c.issuedMT.Root,
		revRoot:    c.revSMT.Root(),
		issueProof: issuedProof,
		revProof:   &rProof,
	}, nil
}
