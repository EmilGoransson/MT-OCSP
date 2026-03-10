package main

import (
	"crypto/sha256"
	"log/slog"
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
	issueProof *merkletree.Proof
	revProof   *smt.SparseMerkleProof
}

func NewEmptyTree() *CombinedTree {
	return &CombinedTree{root: nil, date: time.Now(), issuedMT: nil, revSMT: nil}
}

// TODO: Perhaps create function that takes input blocks for MT and input blocks for SparseMerkleTree & adds them to tree?
func NewCombinedTree(issuedCerts [][]byte, revokedCerts [][]byte) (*CombinedTree, error) {
	// To be changed
	if len(issuedCerts) <= 0 {
		slog.Warn("issued cert is empty")
	}
	if len(revokedCerts) <= 0 {
		slog.Warn("revoked certs initially 0, can be added later")
	}

	merkle, err := NewMerkle(issuedCerts)
	if err != nil {
		return nil, err
	}
	sparseMerkle := NewSparseMerkle()

	tree := CombinedTree{
		root:     nil,
		issuedMT: merkle,
		revSMT:   sparseMerkle,
	}
	_, err = tree.addBulkRevocationToTree(revokedCerts)

	if err != nil {
		return nil, err
	}
	tree.updateGlobalRoot()
	return &tree, nil
}

// TODO: actually implement
// We dont want to create a new SMT for every epoch, only append the last one
func NewCombinedWithExistingRevocationTree(s *SparseMerkleTree, issuedCerts [][]byte, revokedCerts [][]byte) (*CombinedTree, error) {
	// To be changed
	if len(issuedCerts) <= 0 {
		slog.Warn("issued cert is empty")
	}
	if len(revokedCerts) <= 0 {
		slog.Warn("revoked certs initially 0, can be added later")
	}

	merkle, err := NewMerkle(issuedCerts)
	if err != nil {
		return nil, err
	}

	tree := CombinedTree{
		root:     nil,
		issuedMT: merkle,
		revSMT:   s,
	}
	_, err = tree.addBulkRevocationToTree(revokedCerts)

	if err != nil {
		return nil, err
	}
	tree.updateGlobalRoot()
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

func (c *CombinedTree) newMembershipProofRevoked(value []byte) (smt.SparseMerkleProof, error) {
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
func (c *CombinedTree) newMembershipProofIssued(b []byte) (*merkletree.Proof, error) {

	dataBlock, err := ByteToDataBlock(b)

	if err != nil {
		return nil, err
	}

	proof, err := c.issuedMT.Proof(dataBlock)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func (c *CombinedTree) has(b []byte) (bool, error) {
	has, err := c.issuedMT.has(b)
	if err != nil {
		return false, err
	}
	return has, nil
}

// TODO: Implement non membership proof in mt.merkletree
func (c *CombinedTree) newNonMembershipProof(b []byte) (*merkletree.Proof, error) {
	_, err := ByteToDataBlock(b)

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
func (c *CombinedTree) newTreeProof(b []byte) (*CombinedProof, error) {
	// Check if in tree
	// Get issue proof
	// Get rev proof
	rProof, err := c.newMembershipProofRevoked(b)
	if err != nil {
		return nil, err
	}
	dataBlock, err := ByteToDataBlock(b)
	if err != nil {
		return nil, err
	}
	issuedProof, err := c.issuedMT.Proof(dataBlock)
	if err != nil {
		return nil, err
	}
	return &CombinedProof{issueProof: issuedProof, revProof: &rProof}, nil
}
