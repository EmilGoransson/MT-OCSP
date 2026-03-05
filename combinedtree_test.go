package main

import (
	"bytes"
	"testing"

	mt "github.com/txaty/go-merkletree"
)

/*
Test suite co-written using AI (Gemini 3 Pro)
*/
func TestNewCombinedTree(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}

	tree, err := NewCombinedTree(blocks)

	if err != nil {
		t.Fatalf("NewCombinedTree() returned an unexpected error: %v", err)
	}

	if tree == nil {
		t.Fatal("NewCombinedTree() returned a nil tree")
	}

	if tree.issuedMT == nil {
		t.Error("Expected issuedMT to be initialized, but got nil")
	}

	if tree.revSMT == nil {
		t.Error("Expected revSMT to be initialized, but got nil")
	}
}
func TestAddRevocationToTree(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}

	tree, err := NewCombinedTree(blocks)
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}

	testValue := []byte("revoked-credential-id-12345")

	newRoot, err := tree.addRevocationToTree(testValue)
	if err != nil {
		t.Fatalf("addRevocationToTree() returned an error: %v", err)
	}

	if len(newRoot) == 0 {
		t.Error("Expected a valid new root hash, but got an empty byte slice")
	}

	retrievedValue, err := tree.revSMT.Get(testValue)
	if err != nil {
		t.Fatalf("Failed to retrieve value from revSMT: %v", err)
	}

	if !bytes.Equal(retrievedValue, testValue) {
		t.Errorf("Expected retrieved value from SMT to be %s, got %s", testValue, retrievedValue)
	}

	hasValue, err := tree.revSMT.Has(testValue)
	if err != nil {
		t.Fatalf("Failed to check if tree has value: %v", err)
	}
	if !hasValue {
		t.Error("Tree.Has() reported false for a value that was just added")
	}
}
func TestAddBulkRevocationToTree(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}
	tree, err := NewCombinedTree(blocks)
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}

	bulkData := [][]byte{
		[]byte("revoked-id-001"),
		[]byte("revoked-id-002"),
		[]byte("revoked-id-003"),
		[]byte("revoked-id-004"),
	}

	newRoot, err := tree.addBulkRevocationToTree(bulkData)
	if err != nil {
		t.Fatalf("addBulkRevocationToTree() returned an unexpected error: %v", err)
	}

	if len(newRoot) == 0 {
		t.Error("Expected a valid new root hash, but got an empty byte slice")
	}

	for _, testValue := range bulkData {
		hasValue, err := tree.revSMT.Has(testValue)
		if err != nil {
			t.Errorf("Failed to check if tree has value %s: %v", testValue, err)
		}
		if !hasValue {
			t.Errorf("Tree does not contain expected value: %s", testValue)
		}
		retrievedValue, err := tree.revSMT.Get(testValue)
		if err != nil {
			t.Errorf("Failed to retrieve value %s: %v", testValue, err)
		}
		if !bytes.Equal(retrievedValue, testValue) {
			t.Errorf("Expected retrieved value to be %s, got %s", testValue, retrievedValue)
		}
	}
}
func TestGetMembershipProof(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}
	tree, err := NewCombinedTree(blocks)
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}

	testValue := []byte("revoked-credential-proof-test")

	_, err = tree.getMembershipProof(testValue)
	if err != nil {
		t.Fatalf("getMembershipProof() returned an error for empty tree: %v", err)
	}

	_, err = tree.addRevocationToTree(testValue)
	if err != nil {
		t.Fatalf("Failed to add revocation: %v", err)
	}

	_, err = tree.getMembershipProof(testValue)
	if err != nil {
		t.Fatalf("getMembershipProof() returned an error: %v", err)
	}
}

func TestValidateSparseMTMembershipProof(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}
	tree, err := NewCombinedTree(blocks)
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}

	testValue := []byte("revoked-credential-valid-proof")
	wrongValue := []byte("some-other-credential")

	_, err = tree.addRevocationToTree(testValue)
	if err != nil {
		t.Fatalf("Failed to add revocation: %v", err)
	}

	proof, err := tree.getMembershipProof(testValue)
	if err != nil {
		t.Fatalf("Failed to get membership proof: %v", err)
	}

	isValid, err := tree.validateSparseMTMembershipProof(proof, testValue)
	if err != nil {
		t.Fatalf("validateSparseMTMembershipProof() returned an error: %v", err)
	}
	if !isValid {
		t.Error("Expected membership proof to be valid, but got false")
	}

	isWrongValid, err := tree.validateSparseMTMembershipProof(proof, wrongValue)
	if err != nil {
		t.Fatalf("validateSparseMTMembershipProof() returned an error on wrong value: %v", err)
	}
	if isWrongValid {
		t.Error("Expected membership proof to be invalid for a wrong value, but got true")
	}
}

func TestValidateSparseMTNonMembershipProof(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}
	tree, err := NewCombinedTree(blocks)
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}

	dummyValue := []byte("dummy-revoked-credential")
	_, err = tree.addRevocationToTree(dummyValue)
	if err != nil {
		t.Fatalf("Failed to add dummy revocation: %v", err)
	}

	nonExistentValue := []byte("valid-credential-not-revoked")

	proof, err := tree.getMembershipProof(nonExistentValue)
	if err != nil {
		t.Fatalf("Failed to get proof for non-existent value: %v", err)
	}

	isValidNonMembership, err := tree.validateSparseMTNonMembershipProof(proof, nonExistentValue)
	if err != nil {
		t.Fatalf("validateSparseMTNonMembershipProof() returned an error: %v", err)
	}
	if !isValidNonMembership {
		t.Error("Expected non-membership proof to be valid, but got false")
	}

	isValidMembership, err := tree.validateSparseMTMembershipProof(proof, nonExistentValue)
	if err != nil {
		t.Fatalf("validateSparseMTMembershipProof() returned an error during negative check: %v", err)
	}
	if isValidMembership {
		t.Error("Expected membership proof to be invalid for a non-existent value, but got true")
	}
}
func TestAddIssuanceToTree(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}
	tree, err := NewCombinedTree(blocks)
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}
	tree.addIssuanceToTree()
}
func TestUpdateGlobalRoot(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("Failed to generate random blocks: %v", err)
	}
	tree, err := NewCombinedTree(blocks)
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}

	if tree.root != nil {
		t.Error("Expected root to be nil on a fresh tree")
	}

	_, err = tree.addRevocationToTree([]byte("credential-001"))
	if err != nil {
		t.Fatalf("addRevocationToTree() failed: %v", err)
	}
	if len(tree.root) == 0 {
		t.Error("Expected root to be set after mutation, got empty")
	}

	rootAfterFirst := make([]byte, len(tree.root))
	copy(rootAfterFirst, tree.root)

	_, err = tree.addRevocationToTree([]byte("credential-002"))
	if err != nil {
		t.Fatalf("addRevocationToTree() failed: %v", err)
	}
	if bytes.Equal(rootAfterFirst, tree.root) {
		t.Error("Expected root to change after second mutation, but it stayed the same")
	}
	/*
		Not possible with current NewCombinedTree since it's currently filled with random blocks

		tree2, err := NewCombinedTree()
		if err != nil {
			t.Fatalf("Failed to set up second tree: %v", err)
		}
		_, err = tree2.addBulkRevocationToTree([][]byte{
			[]byte("credential-001"),
			[]byte("credential-002"),
		})
		if err != nil {
			t.Fatalf("addBulkRevocationToTree() failed: %v", err)
		}
		if !bytes.Equal(tree.root, tree2.root) {
			t.Error("Expected identical trees to produce identical roots")
		}
	*/
}
func TestNewMerkle_SortsLeaves(t *testing.T) {
	blocks := []mt.DataBlock{
		&certHash{hash: []byte{200, 200, 200}},
		&certHash{hash: []byte{10, 10, 10}},
		&certHash{hash: []byte{150, 150, 150}},
		&certHash{hash: []byte{50, 50, 50}},
		&certHash{hash: []byte{100, 100, 100}},
	}

	tree, err := NewMerkle(blocks)
	if err != nil {
		t.Fatalf("NewMerkle() returned an unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("NewMerkle() returned a nil tree")
	}

	for i := 0; i < len(blocks)-1; i++ {
		dataI, _ := blocks[i].Serialize()
		dataJ, _ := blocks[i+1].Serialize()

		if bytes.Compare(dataI, dataJ) > 0 {
			t.Errorf("Blocks are not sorted correctly!\nIndex %d: %v\nIndex %d: %v",
				i, dataI, i+1, dataJ)
		}
	}
}
