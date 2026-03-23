package ocsp

import (
	"crypto/sha256"
	"fmt"
	"merkle-ocsp/internal/tree"

	"github.com/celestiaorg/smt"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	mt "github.com/txaty/go-merkletree"
)

func Verify(m *Response, sl *SignedLandmark, hash []byte, block mt.DataBlock) (bool, error) {
	// Verify CombinedProof
	if m == nil || m.Proof == nil || m.Proof.CombinedProof == nil || sl == nil {
		return false, fmt.Errorf("bad Response")
	}
	verify, err := mt.Verify(block, m.Proof.CombinedProof.IssueProof, m.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
	if err != nil {
		return false, fmt.Errorf("verifying issue-proof, %v", err)
	}
	switch m.Status {
	// We expect inclusion in issue-proof & exclusion (inclusion but for empty hash) in revoke proof
	case Good:
		{
			notRevoked := smt.VerifyProof(*m.Proof.CombinedProof.RevProof, m.Proof.CombinedProof.RevRoot, hash, []byte{}, sha256.New())
			if !verify || !notRevoked {
				return false, fmt.Errorf("bad proof for good, expected, true, true, got: %t, %t  ", verify, notRevoked)
			}
		}
		// We expect inclusion in issue-proof & inclusion in revoke proof
	case Revoked:
		{
			verifyRev := smt.VerifyProof(*m.Proof.CombinedProof.RevProof, m.Proof.CombinedProof.RevRoot, hash, hash, sha256.New())
			if !verify || !verifyRev {
				return false, fmt.Errorf("bad proof for revoked, expected, true, true, got: %t, %t  ", verify, verifyRev)
			}
		}
	case Unknown:
		{ // If not issued we expect a proof verifying the exclusion. TODO: not implemented yet
			if verify {
				return false, fmt.Errorf("bad proof for unknown, expected, false, got: %t ", verify)
			}
		}
	default:
		{
			return false, fmt.Errorf("bad status, %d", m.Status)
		}
	}
	//Calculate the hash from issue + rev:
	hasher := sha256.New()
	hasher.Write(m.Proof.CombinedProof.IssueRoot)
	hasher.Write(m.Proof.CombinedProof.RevRoot)
	hash = hasher.Sum(nil)
	// use the hash to verify its inclusion in the Log:
	err = proof.VerifyInclusion(
		rfc6962.DefaultHasher,
		m.Proof.logIndex,
		sl.LogSize,
		hash,
		m.Proof.logProof,
		sl.LogRoot,
	)
	if err != nil {
		return false, fmt.Errorf("Log inclusion proof failed: %w", err)
	}

	return true, nil
}
