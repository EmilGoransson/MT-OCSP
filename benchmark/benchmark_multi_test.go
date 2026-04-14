package benchmark

import (
	"fmt"
	"math"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/tree"
	"testing"
)

// How many issued certificates that is added to the issue tree
var issuedCounts = []int{10, 100, 1_000, 10_000, 100_000}

// How many % of certs that are revoked
var RevokedRatios = []float64{.05, .01, .15}

var EpochCounts = []int{1, 10, 50, 100, 500, 1000}

func buildMultiEpochLandmarks(t testing.TB, totalIssued, totalRevoked, numEpochs int) ([]*ocsp.Landmark, []byte) {
	t.Helper()

	log, err := tree.NewLog()
	if err != nil {
		t.Fatalf("creating new log: %v", err)
	}

	issuedPerEpoch := totalIssued / numEpochs
	revokedPerEpoch := totalRevoked / numEpochs

	var allIssuedHashes [][]byte
	var allRevokedHashes [][]byte

	for i := 0; i < totalIssued; i++ {
		allIssuedHashes = append(allIssuedHashes, hashUint64(uint64(i+1)))
	}
	for i := 0; i < totalRevoked; i++ {
		allRevokedHashes = append(allRevokedHashes, hashUint64(uint64(i+1)))
	}

	sparseTree := tree.NewSparse()
	var landmarks []*ocsp.Landmark

	for j := 0; j < numEpochs; j++ {
		startIssue := j * issuedPerEpoch
		endIssue := startIssue + issuedPerEpoch
		if j == numEpochs-1 {
			endIssue = totalIssued
		}

		startRev := j * revokedPerEpoch
		endRev := startRev + revokedPerEpoch
		if j == numEpochs-1 {
			endRev = totalRevoked
		}

		epochIssued := allIssuedHashes[startIssue:endIssue]
		epochRevoked := allRevokedHashes[startRev:endRev]

		combined, err := tree.NewCombined(epochIssued, epochRevoked, sparseTree)
		if err != nil {
			t.Fatalf("epoch %d: creating new combined tree: %v", j, err)
		}

		landmark, err := ocsp.NewLandmark(log, combined)
		if err != nil {
			t.Fatalf("epoch %d: creating new landmark: %v", j, err)
		}

		landmarks = append(landmarks, landmark)

		sparseTree = combined.RevSMT
	}
	return landmarks, allRevokedHashes[0]
}

func BenchmarkProofSizeEpochFrequency(b *testing.B) {
	for _, numIssued := range issuedCounts {
		for _, numRevoked := range RevokedRatios {
			tRevoked := int(math.Max(1, math.Round(float64(numIssued)*numRevoked)))
			for _, numEpochs := range EpochCounts {
				b.Run(fmt.Sprintf("issued=%d/revoked=%.0f%%/epochs=%d", numIssued, numRevoked*100, numEpochs), func(b *testing.B) {
					landmarks, target := buildMultiEpochLandmarks(b, numIssued, tRevoked, numEpochs)

					issueLandmark := landmarks[0]

					newestLandmark := landmarks[len(landmarks)-1]

					b.ResetTimer()
					for i := 0; i < b.N; i++ {

						resp, err := ocsp.NewResponse(target, issueLandmark, newestLandmark)
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
}
