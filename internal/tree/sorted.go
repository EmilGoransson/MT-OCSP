package tree

import (
	"bytes"
	"fmt"
	"sort"

	mt "github.com/txaty/go-merkletree"
)

var DefaultMerkleConfig = &mt.Config{
	DisableLeafHashing: true,
	SortSiblingPairs:   true,
	Mode:               mt.ModeTreeBuild,
}

type certHash struct {
	hash []byte
}
type Sorted struct {
	*mt.MerkleTree
}
type test interface {
}
type ExclusionProofSorted struct {
	lVal   []byte
	rVal   []byte
	lProof *mt.Proof
	rProof *mt.Proof
}

func (t *certHash) Serialize() ([]byte, error) {
	return t.hash, nil
}

func ByteSliceToDataBlock(b [][]byte) ([]mt.DataBlock, error) {
	var blocks []mt.DataBlock

	for _, bSlice := range b {
		block, err := ByteToDataBlock(bSlice)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}
func ByteToDataBlock(b []byte) (mt.DataBlock, error) {
	block := &certHash{
		hash: b,
	}
	return block, nil
}

// TODO:

func ValidateExclusion(b []byte, proof *ExclusionProofSorted, root []byte, c *mt.Config) (bool, error) {

	if proof == nil {
		return false, fmt.Errorf("expected a non-nil proof")
	}

	// 3 cases
	//case 2 // validate the case
	if proof.lProof != nil && proof.rProof != nil {
		// You expect b to be in the middle, so
		if bytes.Compare(b, proof.lVal) <= 0 || bytes.Compare(b, proof.rVal) >= 0 {
			return false, fmt.Errorf("expected lVal < b < rVal: lVal: %x, b: %x, rVal: %x", proof.lVal, b, proof.rVal)
		}
		lBlock, err := ByteToDataBlock(proof.lVal)
		if err != nil {
			return false, err
		}
		rBlock, err := ByteToDataBlock(proof.rVal)
		if err != nil {
			return false, err
		}
		validLeft, err := mt.Verify(lBlock, proof.lProof, root, c)
		if err != nil {
			return false, err
		}
		validRight, err := mt.Verify(rBlock, proof.rProof, root, c)
		if err != nil {
			return false, err
		}
		if !validLeft || !validRight {
			return false, fmt.Errorf("bad proof: expected true, true, got: validLeft %t, validRight %t", validLeft, validRight)
		}
		return true, nil
	}
	// Case 1, insertion at the left-most
	if proof.lProof != nil {
		if bytes.Compare(b, proof.lVal) > 0 {
			return false, fmt.Errorf("bad proof: expected b to be smaller than lVal, b: %x, lVal: %x", b, proof.lVal)
		}
		lBlock, err := ByteToDataBlock(proof.lVal)
		if err != nil {
			return false, err
		}
		validLeft, err := mt.Verify(lBlock, proof.lProof, root, c)
		if err != nil {
			return false, err
		}
		if !validLeft {
			return false, fmt.Errorf("bad proof: expected true, got: %t", validLeft)
		}
		return true, nil

	}
	// Case 3
	if proof.rProof != nil {
		if bytes.Compare(b, proof.rVal) < 0 {
			return false, fmt.Errorf("bad format: expected b to be larger than rVal, b: %x, lVal: %x", b, proof.rVal)
		}
		rBlock, err := ByteToDataBlock(proof.rVal)
		if err != nil {
			return false, err
		}
		validRight, err := mt.Verify(rBlock, proof.rProof, root, c)
		if err != nil {
			return false, err
		}
		if !validRight {
			return false, fmt.Errorf("bad proof: expected true, got: %t", validRight)
		}
		return true, nil
	}
	return false, fmt.Errorf("bad proof format")
}
func (t *Sorted) ValidateExclusion(b []byte, proof *ExclusionProofSorted) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("expected a non-nil proof")
	}

	// 3 cases
	//case 2 // validate the case
	if proof.lProof != nil && proof.rProof != nil {
		// You expect b to be in the middle, so
		if bytes.Compare(b, proof.lVal) <= 0 || bytes.Compare(b, proof.rVal) >= 0 {
			return false, fmt.Errorf("expected lVal < b < rVal: lVal: %x, b: %x, rVal: %x", proof.lVal, b, proof.rVal)
		}
		lBlock, err := ByteToDataBlock(proof.lVal)
		if err != nil {
			return false, err
		}
		rBlock, err := ByteToDataBlock(proof.rVal)
		if err != nil {
			return false, err
		}
		validLeft, err := t.Verify(lBlock, proof.lProof)
		if err != nil {
			return false, err
		}
		validRight, err := t.Verify(rBlock, proof.rProof)
		if err != nil {
			return false, err
		}
		if !validLeft || !validRight {
			return false, fmt.Errorf("bad proof: expected true, true, got: validLeft %t, validRight %t", validLeft, validRight)
		}
		return true, nil
	}
	// Case 1, insertion at the left-most
	if proof.lProof != nil {
		if bytes.Compare(b, proof.lVal) > 0 {
			return false, fmt.Errorf("bad proof: expected b to be smaller than lVal, b: %x, lVal: %x", b, proof.lVal)
		}
		lBlock, err := ByteToDataBlock(proof.lVal)
		if err != nil {
			return false, err
		}
		validLeft, err := t.Verify(lBlock, proof.lProof)
		if err != nil {
			return false, err
		}
		if !validLeft {
			return false, fmt.Errorf("bad proof: expected true, got: %t", validLeft)
		}
		return true, nil

	}
	// Case 3
	if proof.rProof != nil {
		if bytes.Compare(b, proof.rVal) < 0 {
			return false, fmt.Errorf("bad format: expected b to be larger than rval, b: %x, lVal: %x", b, proof.rVal)
		}
		rBlock, err := ByteToDataBlock(proof.rVal)
		if err != nil {
			return false, err
		}
		validRight, err := t.Verify(rBlock, proof.rProof)
		if err != nil {
			return false, err
		}
		if !validRight {
			return false, fmt.Errorf("bad proof: expected true, got: %t", validRight)
		}
		return true, nil
	}
	return false, fmt.Errorf("bad proof format")
}

func (t *Sorted) NewNonMemberProof(hash []byte) (*ExclusionProofSorted, error) {
	block, err := ByteToDataBlock(hash)
	if err != nil {
		return nil, err
	}
	ret := &ExclusionProofSorted{
		lVal:   nil,
		rVal:   nil,
		lProof: nil,
		rProof: nil,
	}
	// Get the leaves
	leaves := t.Leaves
	if len(t.Leaves) == 0 {
		return nil, fmt.Errorf("tree is empty")
	}
	var strings []string
	for _, leave := range leaves {
		strings = append(strings, string(leave))
	}

	serialized, _ := block.Serialize()
	s := string(serialized)
	// This should find the index to insert at, however, for some reason the leaves are hashed in issue-tree?
	index := sort.SearchStrings(strings, s)
	// Now handle cases
	if index < 0 || index > len(leaves) {
		return nil, err
	}
	// TODO: test with large util if its inserted at correct index
	// What happens if there is a single util in the issue tree?
	// Case 1, index = 0, we get the inclusion proof for index = 0, Case 3, if it should be inserted in the end, validate that its len-1
	if err != nil {
		return nil, err
	}
	// Case 1

	if index <= 0 {
		leaf := leaves[index]
		bDatablockL, err := ByteToDataBlock(leaf)
		if err != nil {
			return nil, err
		}
		ret.lProof, err = t.Proof(bDatablockL)
		if err != nil {
			return nil, err
		}
		ret.lVal = leaves[index]
		ret.rProof = nil
		return ret, nil
	}
	// Case 3
	if index == len(leaves) {
		leafR := leaves[index-1]
		bDatablockR, err := ByteToDataBlock(leafR)
		ret.lProof = nil
		ret.rProof, err = t.Proof(bDatablockR)
		ret.rVal = leafR
		if err != nil {
			return nil, err
		}
		return ret, nil
	}
	// Case 2, middle case. two proofs
	// insert at 2 =>
	// arr[1] < insert <arr[2]
	// Two proofs,
	leafR := leaves[index]
	bDatablockR, err := ByteToDataBlock(leafR)
	leafL := leaves[index-1]
	bDatablockL, err := ByteToDataBlock(leafL)
	if err != nil {
		return nil, err
	}
	proofL, err := t.Proof(bDatablockL)
	if err != nil {
		return nil, err
	}
	proofR, err := t.Proof(bDatablockR)
	if err != nil {
		return nil, err
	}
	ret.lProof = proofL
	ret.rProof = proofR
	ret.lVal = leafL
	ret.rVal = leafR
	return ret, nil
}

// // TEMP solution, if implemented correctly can be o(logn) prob
func (t *Sorted) has(hash []byte) (bool, error) {
	leaves := t.MerkleTree.Leaves
	for _, leaf := range leaves {
		if bytes.Compare(hash, leaf) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// NewSorted Takes [][]byte slices as input and converts it to []Datablock
func NewSorted(byteBlocks [][]byte) (*Sorted, error) {
	blocks, err := ByteSliceToDataBlock(byteBlocks)
	if err != nil {
		return nil, err
	}

	// Sort the blocks before inserting
	sort.Slice(blocks, func(i, j int) bool {
		dataI, _ := blocks[i].Serialize()
		dataJ, _ := blocks[j].Serialize()
		return bytes.Compare(dataI[:], dataJ[:]) < 0
	})
	// If there is a single block, do what?
	// TOOD: make sure to verify that this does not break the proofs
	if len(blocks) == 1 {
		emptyBlock, err := ByteToDataBlock([]byte{})
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, emptyBlock)
	}
	// the number of data blocks must be greater than 1
	mtTree, err := mt.New(DefaultMerkleConfig, blocks)
	if err != nil {
		return nil, err
	}
	var tree = &Sorted{mtTree}

	return tree, nil
}
