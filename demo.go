package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"merkle-ocsp/internal/cert"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/tree"

	"github.com/celestiaorg/smt"
	mt "github.com/txaty/go-merkletree"
)

func demo() {

	revokedCerts := [][]byte{
		[]byte("revoked-id-001"),
		[]byte("revoked-id-002"),
		[]byte("revoked-id-003"),
		[]byte("revoked-id-004"),
	}
	issuedCerts := [][]byte{
		[]byte("issued-id-001"),
		[]byte("issued-id-002"),
		[]byte("issued-id-003"),
		[]byte("issued-id-004"),
	}
	// CA
	//temp storage Epoch => Landmark => trees
	// Or Date => Landmark => Trees

	// Cert hash => check each landmark
	store := make(map[uint64]*ocsp.Landmark)

	log, _ := tree.NewLog()

	revocationTree := tree.NewSparse()
	caKey, _ := cert.NewRootCertificateAndKey(2048)
	certs, _ := cert.NewListRandomCertificatesWithKey(10, caKey.PKey)
	initTree, _ := tree.NewCombined(issuedCerts, nil, revocationTree)
	var revoked [][]byte
	for i, cert := range certs {
		if i%5 == 0 {
			revoked = append(revoked, cert)
		}
	}
	_, _ = initTree.AddBulkRevocationToTree(revokedCerts)
	//Store the combinedTree
	//combinedTreeStore[0] = *initTree
	_ = log.AppendToLog(initTree.Root)
	// Generate landmark to publish
	landmark, _ := ocsp.NewLandmark(log, initTree)
	store[0] = landmark
	// Sign the lm
	signed, _ := landmark.NewSignedHead(caKey.PKey, crypto.SHA256)

	// Finds the oldest lm that contains test
	hash := []byte("test")
	var foundTree *ocsp.Landmark
	for _, lm := range store {
		if has, _ := lm.Ctree.Has(hash); has {
			foundTree = lm
		}
	}
	fmt.Println("found tree, ", foundTree)

	// Signed sent to client

	// From client perspective
	// 1. Verifies the signature
	// Calculate the hash
	hasher := crypto.SHA256.New()
	// Converts tree size to []byte
	treeSizeHash := make([]byte, 8)
	size := signed.LogSize
	binary.BigEndian.PutUint64(treeSizeHash, size)
	timeHash, err := signed.Date.MarshalBinary()
	if err != nil {
		_ = fmt.Errorf("marshaling time, %v", err)
	}
	hasher.Write(signed.LogRoot)
	hasher.Write(treeSizeHash)
	hasher.Write(timeHash)
	checksum := hasher.Sum(nil)

	pubKey := caKey.PKey.PublicKey

	err = rsa.VerifyPKCS1v15(&pubKey, crypto.SHA256, checksum, signed.SignedHashData)
	if err != nil {
		_ = fmt.Errorf("verifying data, %v", err)
	}
	// If no error -> Signature is valid -> We can trust the data.

	// Wants to validate a cert, t.ex revokedCerts[0]
	// Sent to server (revokedCerts[0] OR ID?)
	certToCheck := issuedCerts[1]
	// Makes a request -> OCSPResponder

	// OCSP responder
	receivedCert := certToCheck
	fmt.Println(receivedCert)

	// Checks its status: e.g: ValidateCert(receivedCert) // should prov be in its own folder /verify
	// Need function to find landmark index and the combined Tree
	// Find correct combinedTree using date? => Use combinedTree.root to find correct landmark
	// lets say we find correct combinedTree initTree
	fetchedTree := initTree
	fetchedLog := log
	// NewLandmarkProof currently takes a landmark, however, it only uses combinedTree & the issue log to generate proof.
	// Lets say that we find combinedTree & issue log
	notReallyLandmark := landmark

	// We now either hash the cert or use its ID (how does it OCSP & also smaller)
	// Generate OCSP response
	fmt.Println(fetchedTree)
	fmt.Println(fetchedLog)
	res, _ := ocsp.NewResponse(certToCheck, notReallyLandmark)

	// to be encoded and sent to the client

	// Client receives the response, and should validate it
	// ValidateProof() should:
	// 1. Validate the proof of the combinedProof and make sure it is valid together with status, store the root of the calculated tree
	// 2. Validate that the previously calculated root exists in the log using signed.logRoot
	h := sha256.New()
	h.Write(certToCheck)
	hCert := h.Sum(nil)
	block, _ := tree.ByteToDataBlock(certToCheck)

	// Move to Verify .go or something
	// Client should import
	switch res.Status {
	case ocsp.Good:
		block, _ := tree.ByteToDataBlock(certToCheck)
		verify, err := mt.Verify(block, res.Proof.CombinedProof.IssueProof, res.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
		verifyRev := smt.VerifyProof(*res.Proof.CombinedProof.RevProof, res.Proof.CombinedProof.RevRoot, hCert, []byte{}, sha256.New())
		fmt.Println("In issuance tree:", verify, err)
		fmt.Println("Not in revocation tree:", verifyRev)

	case ocsp.Revoked:
		block, _ := tree.ByteToDataBlock(certToCheck)
		verify, err := mt.Verify(block, res.Proof.CombinedProof.IssueProof, res.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
		verifyRev := smt.VerifyProof(*res.Proof.CombinedProof.RevProof, res.Proof.CombinedProof.RevRoot, hCert, hCert, sha256.New())
		fmt.Println("In issuance tree:", verify, err)
		fmt.Println("In revocation tree:", verifyRev)

	case ocsp.Unknown:
		fmt.Println("status = unknown: todo, implement this")
		//todo, revocation proof as a non-issued proof?
	}

	// If e.g status = good,

	// ??? why does mt.MerkleTree need a tree to verify? switch lib?
	verify, err := mt.Verify(block, res.Proof.CombinedProof.IssueProof, res.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
	// Value = []byte{} because we got status = good (we expect the key val to point at empty)
	verifyRev := smt.VerifyProof(*res.Proof.CombinedProof.RevProof, res.Proof.CombinedProof.RevRoot, hCert, []byte{}, sha256.New())
	// The two "proof" needs their head-hash to verify against. If implemented from scratch, you could technically compare it "higher up" since on this implementation they are children och the combinedTrees root.
	// if you calculate both verify and verifyRev up until its highest hash, and then hash both of them together, they should equal combinedTrees root hash.
	// Bandaid fix: include the root-certs in the combinedProof.
	fmt.Println("Certificate is in issued Tree: ", verify)
	fmt.Println("Certificate is not in rev-tree (proof is for path = nobyte []byte{}  ", verifyRev)
	if err != nil {
		return
	}
}

// Manual testing
