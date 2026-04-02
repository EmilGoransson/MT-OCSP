package ocsp

import (
	"crypto/sha256"
	"fmt"
	"merkle-ocsp/internal/tree"
	"time"

	"github.com/celestiaorg/smt"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	mt "github.com/txaty/go-merkletree"
)

// Verify is used by the client to verify sent landmark
func Verify(m *Response, sl *SignedLandmark, hash []byte, date time.Time) (bool, error) {
	block, err := tree.ByteToDataBlock(hash)
	if err != nil {
		return false, fmt.Errorf("creating data block, %v", err)
	}
	// Verify CombinedProof
	if m == nil || m.Proof == nil || m.Proof.CombinedProof == nil || sl == nil {
		return false, fmt.Errorf("bad Response")
	}

	nonIssueProof := m.Proof.CombinedProof.NonIssueProof
	switch m.Status {
	// We expect inclusion in issue-proof & exclusion (inclusion but for empty hash) in revoke proof & RevProof = Nil
	//
	case Good:
		{
			if m.Proof.CombinedProof.IssueProof == nil || m.Proof.CombinedProof.RevProof == nil {
				return false, fmt.Errorf("bad proof for status=good, missing proofs")
			}
			// verify date

			verify, err := mt.Verify(block, m.Proof.CombinedProof.IssueProof, m.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
			if err != nil {
				return false, fmt.Errorf("verifying issue-proof, %v", err)
			}
			notRevoked := smt.VerifyProof(*m.Proof.CombinedProof.RevProof, m.Proof.CombinedProof.RevRoot, hash, []byte{}, sha256.New())
			if !verify || !notRevoked || nonIssueProof != nil {
				return false, fmt.Errorf("bad proof for status=good, expected, true, true, got: %t, %t  ", verify, notRevoked)
			}
		}
		// We expect inclusion in issue-proof & inclusion in revoke proof
	case Revoked:
		{
			if m.Proof.CombinedProof.IssueProof == nil || m.Proof.CombinedProof.RevProof == nil {
				return false, fmt.Errorf("bad proof for status=revoked, missing proofs")
			}
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
			// We expect the date to be "correct"

			if m.Proof.CombinedProof.IssueProof != nil {
				return false, fmt.Errorf("bad proof for status=Unknown, expected issueProof to be nil")
			}
			if nonIssueProof == nil {
				return false, fmt.Errorf("expected nonIssueProof to be non-nil")
			}
			// Verify that the date matches the freq period

			epochDate := m.Proof.CombinedProof.IssueDate
			if date.Before(epochDate.Add(-sl.Frequency)) || date.After(epochDate) {
				return false, fmt.Errorf("time not matching: response timestamp %s not in period  [%s, %s]",
					date, epochDate.Add(-sl.Frequency), epochDate)
			}

			verifyExclusionNonIssued, err := tree.ValidateExclusion(hash, nonIssueProof, m.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
			if err != nil {
				return false, fmt.Errorf("verifying nonIssue proof, %v", err)
			}

			if !verifyExclusionNonIssued {
				return false, fmt.Errorf("bad proof for status=Unknown, exclusion verification failed")
			}
		}
	default:
		{
			return false, fmt.Errorf("bad status, %d", m.Status)
		}
	}
	// Verify inclusion for the issue epoch. The revocation proof is from the newest epoch,
	// but the log proof is to the issue epoch combined root.

	// Calculate the hash from issue + rev for the issue epoch:
	hasher := sha256.New()
	hasher.Write(m.Proof.CombinedProof.IssueRoot)
	hasher.Write(m.Proof.CombinedProof.IssueEpochRev)
	combinedRoot := hasher.Sum(nil)

	// Add the date from the proof
	dBytes, err := m.Proof.CombinedProof.IssueDate.MarshalBinary()
	if err != nil {
		return false, fmt.Errorf("marshalling date, %v", err)
	}
	h := sha256.New()
	h.Write(combinedRoot)
	h.Write(dBytes)
	lHash := h.Sum(nil)
	// use the hash to verify its inclusion in the Log:
	err = proof.VerifyInclusion(
		rfc6962.DefaultHasher,
		m.Proof.LogIndex,
		sl.LogSize,
		lHash,
		m.Proof.LogProof,
		sl.LogRoot,
	)
	if err != nil {
		return false, fmt.Errorf("log inclusion proof failed: %w", err)
	}

	// Verify the rev-side against the log

	if m.Status != Unknown {
		dBytes, err := sl.Date.MarshalBinary()

		nHasher := sha256.New()
		nHasher.Write(m.Proof.CombinedProof.RevEpochIssue)
		nHasher.Write(m.Proof.CombinedProof.RevRoot)
		nH := nHasher.Sum(nil)

		dHasher := sha256.New()
		dHasher.Write(nH)
		dHasher.Write(dBytes)
		nHash := dHasher.Sum(nil)

		err = proof.VerifyInclusion(
			rfc6962.DefaultHasher,
			m.Proof.NewestLogIndex,
			sl.LogSize,
			nHash,
			m.Proof.NewestLogProof,
			sl.LogRoot,
		)
		if err != nil {
			return false, fmt.Errorf("newest landmark log inclusion proof failed, %v", err)
		}
	}
	return true, nil
}
