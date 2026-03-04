package main

import (
	"crypto/rand"

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
func generateRandBlocks(size int) (blocks []mt.DataBlock) {
	for i := 0; i < size; i++ {
		certObj, err := getRandomCert()

		block := &certHash{
			hash: getByteHash(certObj.certificate),
		}
		_, err = rand.Read(block.hash)
		handleError(err)
		blocks = append(blocks, block)
	}
	return
}

// inBlocks []mt.DataBlock
func createEmptyMT() *mt.MerkleTree {

	config := &mt.Config{
		DisableLeafHashing: false,
		SortSiblingPairs:   true,
		Mode:               mt.ModeProofGenAndTreeBuild,
	}
	mtTree, _ := mt.New(config, generateRandBlocks(10))
	return mtTree
}
func sortBlocks() {

}

func mtTest() {

	/*

			blocks := generateRandBlocks(4)
		rndBlock := generateRandBlocks(1)
		mtTree := createEmptyMT()
		// Generate proof for every node in the tree
		proofs := mtTree.Proofs
		fmt.Println(proofs)
		// generate proof for a single node



		proof0 := mtTree.Proof(blocks[0])
		fmt.Println(proof0)

		// verify single block
		status, err := mtTree.Verify(blocks[0], proof0)
		fmt.Println(status)

		status, err = mtTree.Verify(rndBlock[0], proof0)

		fmt.Println(status)
	*/
}

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}
