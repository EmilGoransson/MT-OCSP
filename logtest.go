package main

import (
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

type landmarkStore struct {
	id   uint64
	hash []byte
}

func LogTest() error {
	factory := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

	// Only stores / calculates the peeks (see: https://mmr.herodotus.dev/)
	treeRange := factory.NewEmptyRange(0)

	// Therefore, we need to create our own map to store the "Nodes"
	nodeStore := make(map[compact.NodeID][]byte)
	// Stores the "temp" nodes needed to calculate the root when the tree isnt perfect.
	// Needed if for example u want to prove ther existance of one of the emperic nodes (to the side)
	empiricNodeStore := make(map[compact.NodeID][]byte)

	//landmark-hash-store , ID -> Hash
	var storeID uint64 = 0
	var lmStore []landmarkStore
	var indexToProve uint64 = 3
	var hashToProve []byte
	var lmHash []byte

	// To save the nodes treeRange.Append allows you to pass a function that "tracks" the appended nodes
	// This saves the combinedTree struct into the nodeStore map
	saveNode := func(id compact.NodeID, hash []byte) {
		nodeStore[id] = hash
	}
	// same for the calculated landmarks
	saveEphemeralNodes := func(id compact.NodeID, hash []byte) {
		empiricNodeStore[id] = hash
	}
	// Generate some certs
	certs := [][]byte{
		[]byte("Cert-1"),
		[]byte("Cert-2"),
		[]byte("Cert-3"),
		[]byte("Cert-4"),
		[]byte("Cert-5"),
	}

	// Append them to the tree-range and save them to the map
	for index, cert := range certs {
		hash := rfc6962.DefaultHasher.HashLeaf(cert)
		if err := treeRange.Append(hash, saveNode); err != nil {
			return fmt.Errorf("adding to range %v", err)
		}
		if index == 3 {
			hashToProve = hash
		}

		//Calculate the tree-hash (for each landmark)
		var err error
		lmHash, err = treeRange.GetRootHash(saveEphemeralNodes)
		// Add to landmarkStore
		lmStore = append(lmStore, landmarkStore{
			id:   storeID,
			hash: lmHash,
		})
		storeID++

		fmt.Println(lmHash)
		if err != nil {
			return fmt.Errorf("calculating the root-hash")
		}

	}
	fmt.Println(lmStore)
	fmt.Println(nodeStore)
	fmt.Println(empiricNodeStore)

	// Prints leaf-hashes (landmark-hashes) (they have level = 0), landmark 0 = id 0.
	// If you e.g want to prove that LM3 (ID = 3) is a part of the most recent landmark-hash, you generate a proof for ID = 3
	// Also, count nr of leaves at the bottom of the tree (used for proof verif)
	for id, hash := range nodeStore {
		if id.Level == 0 {
			fmt.Printf("Hash for leaf node: %d, %s\n", id.Index, hash)
		}
	}

	// The count of leaves in the tree, should be distributed alongside the root-hash or part of it
	treeSize := uint64(len(certs))
	fmt.Println(treeSize)

	// should return the nodes needed to prove that 3 is in the tree
	proofBuild, _ := proof.Inclusion(indexToProve, treeSize)

	fmt.Println(proofBuild)

	//TODO: finish this
	var hashes [][]byte

	for _, id := range proofBuild.IDs {
		hash, inMap := nodeStore[id]
		if !inMap {
			return fmt.Errorf("node missing from nodeStore, ID: %d, %b", id, hash)
		}
		hashes = append(hashes, hash)
	}
	rehashProof, err := proofBuild.Rehash(hashes, rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		return fmt.Errorf("creating rehash from proofBuild, %v", err)
	}
	fmt.Println(rehashProof)
	fmt.Println("verifying proof")
	err = proof.VerifyInclusion(rfc6962.DefaultHasher, indexToProve, treeSize, hashToProve, rehashProof, lmHash)
	if err != nil {
		return fmt.Errorf("verifying proof failed, %v", err)
	}

	fmt.Println(hashToProve)
	fmt.Println("proof successful")

	return nil

}
