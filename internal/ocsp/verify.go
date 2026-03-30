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

// Verify is used by the client to verify sent landmark
func Verify(m *Response, sl *SignedLandmark, hash []byte) (bool, error) {
	block, err := tree.ByteToDataBlock(hash)
	// Verify CombinedProof
	if m == nil || m.Proof == nil || m.Proof.CombinedProof == nil || sl == nil {
		return false, fmt.Errorf("bad Response")
	}
	nonIssueProof := m.Proof.CombinedProof.NonIssueProof
	switch m.Status {
	// We expect inclusion in issue-proof & exclusion (inclusion but for empty hash) in revoke proof & RevProof = Nil
	case Good:
		{
			verify, err := mt.Verify(block, m.Proof.CombinedProof.IssueProof, m.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
			if err != nil {
				return false, fmt.Errorf("verifying issue-proof, %v", err)
			}
			notRevoked := smt.VerifyProof(*m.Proof.CombinedProof.RevProof, m.Proof.CombinedProof.RevRoot, hash, []byte{}, sha256.New())
			if !verify || !notRevoked || nonIssueProof != nil {
				return false, fmt.Errorf("bad proof for good, expected, true, true, got: %t, %t  ", verify, notRevoked)
			}
		}
		// We expect inclusion in issue-proof & inclusion in revoke proof
	case Revoked:
		{
			verify, err := mt.Verify(block, m.Proof.CombinedProof.IssueProof, m.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
			if err != nil {
				return false, fmt.Errorf("verifying issue-proof, %v", err)
			}
			verifyRev := smt.VerifyProof(*m.Proof.CombinedProof.RevProof, m.Proof.CombinedProof.RevRoot, hash, hash, sha256.New())
			if !verify || !verifyRev || nonIssueProof != nil {
				return false, fmt.Errorf("bad proof for revoked, expected, true, true, got: %t, %t  ", verify, verifyRev)
			}
		}
	case Unknown:
		{ // If not issued we expect a proof verifying the exclusion. TODO: add date validation? We expect the landmark to "cover" the certs date
			if m.Proof.CombinedProof.IssueProof != nil {
				return false, fmt.Errorf("bad proof for Unknown, expected issueProof to be nil")
			}
			if nonIssueProof == nil {
				return false, fmt.Errorf("expected nonIssueProof to be non-nil")
			}
			verifyExclusionNonIssued, err := tree.ValidateExclusion(hash, nonIssueProof, m.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
			if err != nil {
				return false, fmt.Errorf("verifying nonIssue proof, %v", err)
			}

			if !verifyExclusionNonIssued {
				return false, fmt.Errorf("bad proof for Unknown, exclusion verification failed")
			}
		}
	default:
		{
			return false, fmt.Errorf("bad status, %d", m.Status)
		}
	}
	// TODO: this doesnt work if they are of different "epochs", which is the common case
	// Only works if they are from the same epoch
	//Calculate the hash from issue + rev:
	hasher := sha256.New()
	hasher.Write(m.Proof.CombinedProof.IssueRoot) // + "the current periods rev-hash"
	hasher.Write(m.Proof.CombinedProof.RevRoot)   // + "latest landmarks issue-hash"
	// Would have to perform two log-verifications here
	hash = hasher.Sum(nil)
	// use the hash to verify its inclusion in the Log:
	err = proof.VerifyInclusion(
		rfc6962.DefaultHasher,
		m.Proof.LogIndex,
		sl.LogSize,
		hash,
		m.Proof.LogProof,
		sl.LogRoot,
	)
	if err != nil {
		return false, fmt.Errorf("log inclusion proof failed: %w", err)
	}

	return true, nil
}
