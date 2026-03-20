package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/celestiaorg/smt"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	mt "github.com/txaty/go-merkletree"
)

func Verify(m *MerkleResponse, sl *SignedLandmark, hash []byte, block mt.DataBlock) (bool, error) {
	// Verify CombinedProof
	if m == nil || m.proof == nil || m.proof.combinedProof == nil || sl == nil {
		return false, fmt.Errorf("bad MerkleResponse")
	}
	verify, err := mt.Verify(block, m.proof.combinedProof.issueProof, m.proof.combinedProof.issueRoot, defaultMerkleConfig)
	if err != nil {
		return false, fmt.Errorf("verifying issue-proof, %v", err)
	}
	switch m.status {
	// We expect inclusion in issue-proof & exclusion (inclusion but for empty hash) in revoke proof
	case Good:
		{
			notRevoked := smt.VerifyProof(*m.proof.combinedProof.revProof, m.proof.combinedProof.revRoot, hash, []byte{}, sha256.New())
			if !verify || !notRevoked {
				return false, fmt.Errorf("bad proof for good, expected, true, true, got: %t, %t  ", verify, notRevoked)
			}
		}
		// We expect inclusion in issue-proof & inclusion in revoke proof
	case Revoked:
		{
			verifyRev := smt.VerifyProof(*m.proof.combinedProof.revProof, m.proof.combinedProof.revRoot, hash, hash, sha256.New())
			if !verify || !verifyRev {
				return false, fmt.Errorf("bad proof for revoked, expected, true, true, got: %t, %t  ", verify, verifyRev)
			}
		}
	case Unknown:
		{ // If not issued we expect a false inclusion proof
			if verify {
				return false, fmt.Errorf("bad proof for unknown, expected, false, got: %t ", verify)
			}
		}
	default:
		{
			return false, fmt.Errorf("bad status, %d", m.status)
		}
	}
	//Calculate the hash from issue + rev:
	hasher := sha256.New()
	hasher.Write(m.proof.combinedProof.issueRoot)
	hasher.Write(m.proof.combinedProof.revRoot)
	hash = hasher.Sum(nil)
	// use the hash to verify its inclusion in the log:
	err = proof.VerifyInclusion(
		rfc6962.DefaultHasher,
		m.proof.logIndex,
		sl.logSize,
		hash,
		m.proof.logProof,
		sl.logRoot,
	)
	if err != nil {
		return false, fmt.Errorf("log inclusion proof failed: %w", err)
	}

	return true, nil
}
