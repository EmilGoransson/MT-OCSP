package main

import (
	"testing"
)

func TestNewResponse(t *testing.T) {
}
func TestFindTreeTMP(t *testing.T) {
	d := [][]byte{
		[]byte("revoked-id-001"),
		[]byte("revoked-id-002"),
		[]byte("revoked-id-003"),
		[]byte("revoked-id-004"),
	}
	tree, _ := NewCombinedTree(d)

	isInTree, _ := tree.smtHas(d[0])
	if !isInTree {
		t.Error("Expected data to be in tree")
	}
}
func TestGetStatus(t *testing.T) {

}
