package main

import (
	"bytes"
	"testing"
)

func TestAddBulkRevocationToTree(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("failed to generate random blocks: %v", err)
	}
	revTree := NewSparseMerkle()
	tree, err := NewCombinedTree(blocks, nil, revTree)
	if err != nil {
		t.Fatalf("failed to set up test tree: %v", err)
	}

	bulkData := [][]byte{
		[]byte("revoked-id-001"),
		[]byte("revoked-id-002"),
		[]byte("revoked-id-003"),
		[]byte("revoked-id-004"),
	}
	bulkData = HashList(bulkData)
	newRoot, err := tree.addBulkRevocationToTree(bulkData)
	if err != nil {
		t.Fatalf("addBulkRevocationToTree() unexpected error: %v", err)
	}
	if len(newRoot) == 0 {
		t.Fatal("expected non-empty root hash")
	}

	for _, val := range bulkData {
		t.Run(string(val), func(t *testing.T) {
			has, err := tree.revSMT.Has(val)
			if err != nil {
				t.Fatalf("Has(%s): %v", val, err)
			}
			if !has {
				t.Errorf("tree missing expected value: %s", val)
			}

			got, err := tree.revSMT.Get(val)
			if err != nil {
				t.Fatalf("Get(%s): %v", val, err)
			}
			if !bytes.Equal(got, val) {
				t.Errorf("Get(%s) = %s, want %s", val, got, val)
			}
		})
	}

}
func TestValidateSparseMTProofs(t *testing.T) {
	blocks, err := GenerateRandBlocks(10)
	if err != nil {
		t.Fatalf("failed to generate random blocks: %v", err)
	}
	revTree := NewSparseMerkle()
	tree, err := NewCombinedTree(blocks, nil, revTree)
	if err != nil {
		t.Fatalf("failed to set up test tree: %v", err)
	}
	revoked := []byte("revoked-credential")
	revoked = HashCert(revoked)
	notRevoked := []byte("valid-credential-not-revoked")
	notRevoked = HashCert(notRevoked)

	if _, err := tree.addRevocationToTree(revoked); err != nil {
		t.Fatalf("addRevocationToTree: %v", err)
	}

	tests := []struct {
		name          string
		value         []byte
		wantMember    bool
		wantNonMember bool
	}{
		{"revoked credential", revoked, true, false},
		{"non-revoked credential", notRevoked, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := tree.newMembershipProofRevoked(tc.value)
			if err != nil {
				t.Fatalf("newMembershipProofRevoked: %v", err)
			}

			isMember, err := tree.validateSparseMTMembershipProof(proof, tc.value)
			if err != nil {
				t.Fatalf("validateSparseMTMembershipProof: %v", err)
			}
			if isMember != tc.wantMember {
				t.Errorf("membership = %v, want %v", isMember, tc.wantMember)
			}

			isNonMember, err := tree.validateSparseMTNonMembershipProof(proof, tc.value)
			if err != nil {
				t.Fatalf("validateSparseMTNonMembershipProof: %v", err)
			}
			if isNonMember != tc.wantNonMember {
				t.Errorf("non-membership = %v, want %v", isNonMember, tc.wantNonMember)
			}
		})
	}
}
