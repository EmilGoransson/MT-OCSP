package main

import (
	"crypto/sha256"

	"github.com/celestiaorg/smt"
)

type SparseMerkleTree struct {
	hash []byte
	*smt.SparseMerkleTree
}

// TODO: does this work if i want to extend the package?
// TODO: implement the function

func NewSparseMerkle() *SparseMerkleTree {
	nodeStore := smt.NewSimpleMap()
	valueStore := smt.NewSimpleMap()
	// nodeStore.Set(getStringHash("1"), getStringHash("One"))
	return &SparseMerkleTree{nil, smt.NewSparseMerkleTree(nodeStore, valueStore, sha256.New())}
}

func (s *SparseMerkleTree) Root() []byte {
	if s.SparseMerkleTree != nil {
		return s.SparseMerkleTree.Root()
	}
	return s.hash
}

func (s *SparseMerkleTree) Freeze() *SparseMerkleTree {
	if s.SparseMerkleTree != nil {
		return &SparseMerkleTree{
			hash:             s.SparseMerkleTree.Root(),
			SparseMerkleTree: nil,
		}
	}
	return &SparseMerkleTree{
		hash:             s.hash,
		SparseMerkleTree: nil,
	}
}
func getByteHash(bytes []byte) []byte {
	h := sha256.New()
	h.Write(bytes)
	return h.Sum(nil)
}

/*

func smtTest() {

	// Initialise two new key-value store to store the nodes and values of the tree
	nodeStore := smt.NewSimpleMap()
	valueStore := smt.NewSimpleMap()
	tree := smt.NewSparseMerkleTree(nodeStore, valueStore, sha256.New())

	bCert, err := getRandomCert()
	if err != nil {
		panic(err)
	}
	hs := getByteHash(bCert.certificate)
	hKey := bCert.key.PublicKey

	fmt.Println("hs", hs)

	certPrivKeyPEM := new(bytes.Buffer)
	// Encodes the public key
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "MESSAGE",
		Bytes: x509.MarshalPKCS1PublicKey(&hKey),
	})

	// Put public key into tree
	_, _ = tree.Update(hs, certPrivKeyPEM.Bytes())

	// Get the public key
	receivedKeyPairPEMBytes, err := tree.Get(hs)

	if err != nil {
		panic(err)
	}
	// Decodes
	pKey, _ := pem.Decode(receivedKeyPairPEMBytes)

	// Prints public key
	fmt.Println("Pkey: ", pKey.Bytes)

	is, err := tree.Has(hs)
	if err != nil {
		return
	}
	fmt.Println("hash exists?", is)

	is, err = tree.Has(getStringHash("not in tree"))

	fmt.Println("random value in tree?", is)

	// Check if hs = default value
	has, err := tree.Has(hs)
	if err != nil {
		return
	}
	fmt.Println("Tree has hs value?: ", has)

	has, err = tree.Has([]byte("notputintree"))

	fmt.Println("Tree has notputintree?: ", has)

	if err != nil {
		return
	}

	// Generate a Merkle proof for hs
	proof, _ := tree.Prove(hs)
	root := tree.Root() // We also need the current tree root for the proof

	// Verify the Merkle proof for hs.

	// Fetch Hs value
	hsVal, _ := tree.Get(hs)

	// Check if hs = hsVal using proof
	if smt.VerifyProof(proof, root, hs, hsVal, sha256.New()) {
		fmt.Println("Proof verification succeeded.")
	} else {
		fmt.Println("Proof verification failed.")
	}
}
*/
