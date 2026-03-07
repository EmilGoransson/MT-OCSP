package main

import (
	"bytes"
	"sort"

	mt "github.com/txaty/go-merkletree"
)

// TODO: sort the nodes

type certHash struct {
	hash []byte
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

// TODO: implement the function
func has() (bool, error) {
	// Check the tree
	return true, nil
}

// NewMerkle Takes [][]byte slices as input and converts it to []Datablock
func NewMerkle(byteBlocks [][]byte) (*mt.MerkleTree, error) {

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

	if err != nil {
		return nil, err
	}

	return mtTree, nil
}
