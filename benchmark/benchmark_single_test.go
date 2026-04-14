package benchmark

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/tree"
	ocspPb "merkle-ocsp/pb"
	"testing"

	"google.golang.org/protobuf/proto"
)

// How many issued certificates that is added to the issue tree

// How many % of certs that are revoked

func buildLandmark(t testing.TB, issued int, revoked int) (*ocsp.Landmark, []byte) {
	t.Helper()

	log, err := tree.NewLog()
	if err != nil {
		t.Fatalf("creating new log: %v", err)
	}
	issuedHashes := make([][]byte, issued)
	for i := 0; i < issued; i++ {
		issuedHashes[i] = hashUint64(uint64(i + 1))
	}

	revokedHashes := make([][]byte, revoked)
	for i := 0; i < revoked; i++ {
		revokedHashes[i] = hashUint64(uint64(i + 1))
	}

	combined, err := tree.NewCombined(issuedHashes, revokedHashes, tree.NewSparse())
	if err != nil {
		t.Fatalf("creating new combined tree: %v", err)
	}

	landmark, err := ocsp.NewLandmark(log, combined)
	if err != nil {
		t.Fatalf("creating new landmark: %v", err)
	}
	if len(issuedHashes) > 0 {
		return landmark, issuedHashes[0]
	}
	if len(revokedHashes) <= 0 {
		t.Fatalf("issued or revoked needs to be > 0")
	}
	return landmark, revokedHashes[0]
}

func BenchmarkProofSizeIssuedCerts(b *testing.B) {
	for _, n := range issuedCounts {
		n := n
		b.Run(fmt.Sprintf("issued=%d", n), func(b *testing.B) {
			lm, target := buildLandmark(b, n, 0)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := ocsp.NewResponse(target, lm, lm)
				if err != nil {
					b.Fatal(err)
				}
				pbResp := responseToProto(b, resp)
				b.ReportMetric(float64(protoSize(b, pbResp)), "bytes/response")
			}
		})
	}
}

// BenchmarkProofSizeRevokedCerts benchmarks the "pure" size-growth of revoked. By passing a single issued cert
// It avoids defaulting to status=unknown, which would remove the revoked side of the tree
func BenchmarkProofSizeRevokedCerts(b *testing.B) {
	for _, n := range issuedCounts {
		n := n
		b.Run(fmt.Sprintf("revoked=%d", n), func(b *testing.B) {
			lm, target := buildLandmark(b, 1, n)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := ocsp.NewResponse(target, lm, lm)
				if err != nil {
					b.Fatal(err)
				}
				pbResp := responseToProto(b, resp)

				b.ReportMetric(float64(protoSize(b, pbResp)), "bytes/response")
			}
		})
	}
}

func BenchmarkProofSizeIssuedAndRevokedCerts(b *testing.B) {
	for _, n := range issuedCounts {
		for _, p := range RevokedRatios {
			r := int(math.Max(1, math.Round(float64(n)*p)))

			n := n
			b.Run(fmt.Sprintf("issued=%d/revoked=%d/revoked%%=%.0f%%", n, r, p*100), func(b *testing.B) {
				lm, target := buildLandmark(b, n, r)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					resp, err := ocsp.NewResponse(target, lm, lm)
					if err != nil {
						b.Fatal(err)
					}
					pbResp := responseToProto(b, resp)

					b.ReportMetric(float64(protoSize(b, pbResp)), "bytes/response")
				}
			})
		}
	}
}

func hashUint64(v uint64) []byte {
	var serial [8]byte
	binary.BigEndian.PutUint64(serial[:], v)
	sum := sha256.Sum256(serial[:])
	return sum[:]
}

func protoSize(t testing.TB, m proto.Message) int {
	t.Helper()

	if m == nil {
		return 0
	}

	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal proto message: %v", err)
	}
	return len(b)
}

func responseToProto(t testing.TB, resp *ocsp.Response) *ocspPb.Response {
	t.Helper()
	p := ocspPb.ResponseToProto(resp)
	return p
}
