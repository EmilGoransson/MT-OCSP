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
	empericNodeStore := make(map[compact.NodeID][]byte)

	//landmark-hash-store , ID -> Hash
	var storeID uint64 = 0
	var lmStore []landmarkStore

	// To save the nodes treeRange.Append allows you to pass a function that "tracks" the appended nodes
	// This saves the combinedTree struct into the nodeStore map
	saveNode := func(id compact.NodeID, hash []byte) {
		nodeStore[id] = hash
	}
	// same for the calculated landmarks
	saveEphemeralNodes := func(id compact.NodeID, hash []byte) {
		empericNodeStore[id] = hash
	}
	var nrOfLeaves uint64

	// Generate some certs
	certs := [][]byte{
		[]byte("Cert-1"),
		[]byte("Cert-2"),
		[]byte("Cert-3"),
		[]byte("Cert-4"),
		[]byte("Cert-5"),
	}

	// Append them to the tree-range and save them to the map
	for _, cert := range certs {
		hasher := rfc6962.DefaultHasher
		h := hasher.New()
		h.Write(cert)
		hash := h.Sum(nil)
		if err := treeRange.Append(hash, saveNode); err != nil {
			return fmt.Errorf("adding to range %v", err)
		}

		//Calculate the tree-hash (for each landmark)
		lmHash, err := treeRange.GetRootHash(saveEphemeralNodes)
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
	fmt.Println(empericNodeStore)

	// Prints leaf-hashes (landmark-hashes) (they have level = 0), landmark 0 = id 0.
	// If you e.g want to prove that LM3 (ID = 3) is a part of the most recent landmark-hash, you generate a proof for ID = 3
	// Also, count nr of leaves at the bottom of the tree (used for proof verif)
	for id, hash := range nodeStore {
		if id.Level == 0 {
			nrOfLeaves++
			fmt.Printf("Hash for leaf node: %d, %s\n", id.Index, hash)
		}
	}

	// The count of leaves in the tree, should be distributed alongside the root-hash or part of it
	treeSize := nrOfLeaves
	fmt.Println(nrOfLeaves)

	// should return the nodes needed to prove that 3 is in the tree
	proofBuild, _ := proof.Inclusion(3, treeSize)

	fmt.Println(proofBuild)

	//TODO: finish this

	return nil

}
