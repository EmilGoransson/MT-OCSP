package main

import (
	"crypto/rand"

	mt "github.com/txaty/go-merkletree"
)

type certHash struct {
	hash []byte
}

func (t *certHash) Serialize() ([]byte, error) {
	return t.hash, nil
}

// generate dummy data blocks
func generateRandBlocks(size int) (blocks []mt.DataBlock) {
	for i := 0; i < size; i++ {
		block := &certHash{
			hash: make([]byte, 100),
		}
		_, err := rand.Read(block.hash)
		handleError(err)
		blocks = append(blocks, block)
	}
	return
}

func merkleTree() {

}
func sortBlocks() {

}

// todo: figure out config thing?
func main() {
	config := &mt.Config{
		DisableLeafHashing: false,
	}
	blocks := generateRandBlocks(10)

	tree, err := mt.New(config, blocks)
	// GEnerate proof for tree
	handleError(err)

}
func handleError(err error) {
	if err != nil {
		panic(err)
	}
}
