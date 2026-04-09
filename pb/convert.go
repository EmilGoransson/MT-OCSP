package pb

import (
	"fmt"
	"time"

	"github.com/celestiaorg/smt"
	mt "github.com/txaty/go-merkletree"
	"google.golang.org/protobuf/types/known/timestamppb"

	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/tree"
)

func ResponseToProto(r *ocsp.Response) *Response {
	if r == nil {
		return nil
	}
	return &Response{
		Status:    CertStatus(r.Status),
		Timestamp: timestamppb.New(r.Timestamp),
		Proof:     LandmarkProofToProto(r.Proof),
	}
}

func ProtoToResponse(r *Response) (*ocsp.Response, error) {
	if r == nil {
		return nil, fmt.Errorf("nil proto Response")
	}
	p, err := ProtoToLandmarkProof(r.Proof)
	if err != nil {
		return nil, err
	}
	return &ocsp.Response{
		Status:    int8(r.Status),
		Timestamp: r.Timestamp.AsTime(),
		Proof:     p,
	}, nil
}

func LandmarkProofToProto(lp *ocsp.LandmarkProof) *LandmarkProof {
	if lp == nil {
		return nil
	}
	return &LandmarkProof{
		LogProof:       lp.LogProof,
		LogIndex:       lp.LogIndex,
		NewestLogProof: lp.NewestLogProof,
		NewestLogIndex: lp.NewestLogIndex,
		CombinedProof:  CombinedProofToProto(lp.CombinedProof),
	}
}

func ProtoToLandmarkProof(lp *LandmarkProof) (*ocsp.LandmarkProof, error) {
	if lp == nil {
		return nil, nil
	}
	c, err := ProtoToCombinedProof(lp.CombinedProof)
	if err != nil {
		return nil, err
	}
	return &ocsp.LandmarkProof{
		LogProof:       lp.LogProof,
		LogIndex:       lp.LogIndex,
		NewestLogProof: lp.NewestLogProof,
		NewestLogIndex: lp.NewestLogIndex,
		CombinedProof:  c,
	}, nil
}

func CombinedProofToProto(c *ocsp.CombinedProof) *CombinedProof {
	if c == nil {
		return nil
	}
	return &CombinedProof{
		IssueRoot:     c.IssueRoot,
		IssueEpochRev: c.IssueEpochRev,
		RevRoot:       c.RevRoot,
		RevEpochIssue: c.RevEpochIssue,
		IssueDate:     timestamppb.New(c.IssueDate),
		IssueProof:    MerkleProofToProto(c.IssueProof),
		NonIssueProof: ExclusionProofToProto(c.NonIssueProof),
		RevProof:      SparseProofToProto(c.RevProof),
	}
}

func ProtoToCombinedProof(p *CombinedProof) (*ocsp.CombinedProof, error) {
	if p == nil {
		return nil, nil
	}
	var issueDate time.Time
	if p.IssueDate != nil {
		issueDate = p.IssueDate.AsTime()
	}
	return &ocsp.CombinedProof{
		IssueRoot:     p.IssueRoot,
		IssueEpochRev: p.IssueEpochRev,
		RevRoot:       p.RevRoot,
		RevEpochIssue: p.RevEpochIssue,
		IssueDate:     issueDate,
		IssueProof:    ProtoToMerkleProof(p.IssueProof),
		NonIssueProof: ProtoToExclusionProof(p.NonIssueProof),
		RevProof:      ProtoToSparseProof(p.RevProof),
	}, nil
}

func MerkleProofToProto(p *mt.Proof) *MerkleProof {
	if p == nil {
		return nil
	}
	return &MerkleProof{
		Siblings: p.Siblings,
		Path:     p.Path,
	}
}

func ProtoToMerkleProof(p *MerkleProof) *mt.Proof {
	if p == nil {
		return nil
	}
	return &mt.Proof{
		Siblings: p.Siblings,
		Path:     p.Path,
	}
}

func ExclusionProofToProto(e *tree.ExclusionProofSorted) *ExclusionProofSorted {
	if e == nil {
		return nil
	}
	return &ExclusionProofSorted{
		LVal:   e.LVal,
		RVal:   e.RVal,
		LProof: MerkleProofToProto(e.LProof),
		RProof: MerkleProofToProto(e.RProof),
	}
}

func ProtoToExclusionProof(p *ExclusionProofSorted) *tree.ExclusionProofSorted {
	if p == nil {
		return nil
	}
	return &tree.ExclusionProofSorted{
		LVal:   p.LVal,
		RVal:   p.RVal,
		LProof: ProtoToMerkleProof(p.LProof),
		RProof: ProtoToMerkleProof(p.RProof),
	}
}

func SparseProofToProto(p *smt.SparseCompactMerkleProof) *SparseCompactMerkleProof {
	if p == nil {
		return nil
	}
	return &SparseCompactMerkleProof{
		SideNodes:             p.SideNodes,
		NonMembershipLeafData: p.NonMembershipLeafData,
		BitMask:               p.BitMask,
		NumSideNodes:          int32(p.NumSideNodes),
		SiblingData:           p.SiblingData,
	}
}

func ProtoToSparseProof(p *SparseCompactMerkleProof) *smt.SparseCompactMerkleProof {
	if p == nil {
		return nil
	}
	return &smt.SparseCompactMerkleProof{
		SideNodes:             p.SideNodes,
		NonMembershipLeafData: p.NonMembershipLeafData,
		BitMask:               p.BitMask,
		NumSideNodes:          int(p.NumSideNodes),
		SiblingData:           p.SiblingData,
	}
}
