package tree

import (
	"bytes"
	"merkle-ocsp/internal/cert"
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
type SortedMerkleTree struct {
	*mt.MerkleTree
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
func (t *SortedMerkleTree) NewNonMemberProof() {

}

// // TEMP solution, if implemented correctly can be o(logn) prob
func (t *SortedMerkleTree) has(hash []byte) (bool, error) {
	leaves := t.MerkleTree.Leaves
	for _, leaf := range leaves {
		if bytes.Compare(hash, leaf) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// NewMerkle Takes [][]byte slices as input and converts it to []Datablock
func NewMerkle(byteBlocks [][]byte) (*SortedMerkleTree, error) {
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
	mtTree, err := mt.New(DefaultMerkleConfig, blocks)
	var tree = &SortedMerkleTree{mtTree}

	if err != nil {
		return nil, err
	}

	return tree, nil
}
