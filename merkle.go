package main

import (
	"bytes"
	"sort"

	mt "github.com/txaty/go-merkletree"
)

type certHash struct {
	hash []byte
}
type sortedMT struct {
	*mt.MerkleTree
}

func (t *certHash) Serialize() ([]byte, error) {
	return t.hash, nil
}

// generate dummy data blocks
func GenerateRandBlocks(size int) ([][]byte, error) {
	var blocks [][]byte
	for i := 0; i < size; i++ {
		pKey, err := NewKeyPair(2048)
		if err != nil {
			return nil, err
		}
		certObj, err := NewRandomCertificate(pKey, false)

		if err != nil {
			return nil, err
		}
		blocks = append(blocks, certObj)
	}
	return blocks, nil
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
func (t *sortedMT) NewNonMemberProof() {

}

// // TEMP solution, if implemented correctly can be o(logn)?
func (t *sortedMT) has(b []byte) (bool, error) {
	bHash := getByteHash(b)
	leaves := t.MerkleTree.Leaves
	for _, leaf := range leaves {
		if bytes.Compare(bHash, leaf) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// NewMerkle Takes [][]byte slices as input and converts it to []Datablock
func NewMerkle(byteBlocks [][]byte) (*sortedMT, error) {

	blocks, err := ByteSliceToDataBlock(byteBlocks)
	if err != nil {
		return nil, err
	}

	config := &mt.Config{
		// Values hashed before placed in certHash (Should we?)
		DisableLeafHashing: false,
		SortSiblingPairs:   true,
		Mode:               mt.ModeTreeBuild,
	}

	// Sort the blocks before inserting TOOD:verify they r actually getting sorted
	sort.Slice(blocks, func(i, j int) bool {
		dataI, _ := blocks[i].Serialize()
		dataJ, _ := blocks[j].Serialize()
		return bytes.Compare(dataI[:], dataJ[:]) < 0
	})
	mtTree, err := mt.New(config, blocks)
	var tree = &sortedMT{mtTree}

	if err != nil {
		return nil, err
	}

	return tree, nil
}
