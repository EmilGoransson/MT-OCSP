package main

import (
	"bytes"
	"fmt"
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
func GenerateRandBlocks(size int) ([]mt.DataBlock, error) {
	var blocks []mt.DataBlock
	for i := 0; i < size; i++ {
		certObj, err := getRandomCert()

		block := &certHash{
			hash: getByteHash(certObj.certificate),
		}
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

// TODO: Figure out how to do with "input" blocks for merkle.go, random blocks?

func NewMerkle(blocks []mt.DataBlock) (*mt.MerkleTree, error) {

	config := &mt.Config{
		// Values hashed before placed in certHash (Should we?)
		// DisableLeafHashing: false,
		SortSiblingPairs: true,
		Mode:             mt.ModeTreeBuild,
	}

	// Sort the blocks before inserting
	sort.Slice(blocks, func(i, j int) bool {
		dataI, _ := blocks[i].Serialize()
		dataJ, _ := blocks[j].Serialize()
		return bytes.Compare(dataI[:], dataJ[:]) < 0
	})
	fmt.Println("---")

	mtTree, err := mt.New(config, blocks)

	if err != nil {
		return nil, err
	}

	return mtTree, nil
}
