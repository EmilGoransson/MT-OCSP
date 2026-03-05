package main

import (
	"bytes"
	"testing"
)

func TestNewCombinedTree(t *testing.T) {
	tree, err := NewCombinedTree()

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
	tree, err := NewCombinedTree()
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
func TestAddBulkRevocationToTree_Success(t *testing.T) {
	tree, err := NewCombinedTree()
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
func TestAddIssuanceToTree(t *testing.T) {
	tree, err := NewCombinedTree()
	if err != nil {
		t.Fatalf("Failed to set up test tree: %v", err)
	}
	tree.addIssuanceToTree()
}
