package benchmark

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/tree"
	ocspPb "merkle-ocsp/pb"
	"slices"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"google.golang.org/protobuf/proto"
)

// How many issued certificates that is added to the issue tree
var issuedCounts = []int{10, 100, 1_000, 10_000, 100_000, 100_000_0}

// How many % of certs that are revoked
var RevokedRatios = []float64{0.01, .05, .15}

var EpochCounts = []int{1, 100, 1000}

func buildMultiEpochLandmarks(t testing.TB, totalIssued, totalRevoked, numEpochs int, status ocsp.Status) ([]*ocsp.Landmark, []byte) {
	t.Helper()
	l, err := tree.NewLog()
	if err != nil {
		t.Fatalf("creating new log: %v", err)
	}

	issuedPerEpoch := totalIssued / numEpochs
	revokedPerEpoch := totalRevoked / numEpochs

	allIssuedHashes := make([][]byte, totalIssued)
	for i := range allIssuedHashes {
		allIssuedHashes[i] = hashUint64(uint64(i + 1))
	}

	// Good skip hash[0] so the target cert is not revoked
	revokedStart := 0
	if status == ocsp.Good {
		revokedStart = 1
	}
	allRevokedHashes := make([][]byte, 0, totalRevoked)
	for i := 0; i < totalRevoked; i++ {
		allRevokedHashes = append(allRevokedHashes, hashUint64(uint64(i+1+revokedStart)))
	}

	sparseTree := tree.NewSparse()
	landmarks := make([]*ocsp.Landmark, 0, numEpochs)

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
			t.Fatalf("epoch %d: creating combined tree: %v", j, err)
		}

		landmark, err := ocsp.NewLandmark(l, combined)
		if err != nil {
			t.Fatalf("epoch %d: creating landmark: %v", j, err)
		}

		landmarks = append(landmarks, landmark)
		sparseTree = combined.RevSMT
		if j < numEpochs-1 {
			combined.RevSMT = combined.RevSMT.Freeze()
		}
	}

	var target []byte
	switch status {
	case ocsp.Good:
		target = allIssuedHashes[0]
	case ocsp.Revoked:
		target = allRevokedHashes[0]
	case ocsp.Unknown:
		target = hashUint64(math.MaxUint64)
	}

	return landmarks, target
}

func runProofSizeBenchmark(b *testing.B, status ocsp.Status) {
	b.Helper()
	for _, numIssued := range issuedCounts {
		for _, revokedRatio := range RevokedRatios {
			tRevoked := int(math.Round(float64(numIssued) * revokedRatio))
			for _, numEpochs := range EpochCounts {
				name := fmt.Sprintf("issued=%d/revoked=%.0f%%/epochs=%d", numIssued, revokedRatio*100, numEpochs)
				b.Run(name, func(b *testing.B) {
					landmarks, target := buildMultiEpochLandmarks(b, numIssued, tRevoked, numEpochs, status)
					var issueLandmark *ocsp.Landmark
					issueLandmark, err := getLandmarkFromBytes(target, landmarks)
					if err != nil {
						log.Fatalf("finding hash in landmarks")
					}

					if err != nil {
						log.Fatalf("finding landmark from bytes")
					}
					// Unknown case (Since unknwon dont have a "real" date (since it benchmark), we simply take the date of the first lm
					if issueLandmark == nil {

						fakeFrequency := time.Hour
						fakeDate := landmarks[0].Date.Add(-time.Minute)

						issueLandmark, err = getLandmarkFromDate(fakeDate, fakeFrequency, landmarks)
						if err != nil {
							log.Fatalf("landmark from date")
						}
					}

					newestLandmark := landmarks[len(landmarks)-1]

					sampleResp, err := ocsp.NewResponse(target, issueLandmark, newestLandmark)
					if sampleResp.Status != int8(status) {
						log.Fatalf("status mismatch %d != %d", sampleResp.Status, int8(status))
					}
					if err != nil {
						b.Fatal(err)
					}
					samplePbResp := responseToProto(b, sampleResp)
					respSize := float64(protoSize(b, samplePbResp))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						// Now we are ONLY benchmarking the speed of NewResponse
						_, err := ocsp.NewResponse(target, issueLandmark, newestLandmark)
						if err != nil {
							b.Fatal(err)
						}
					}
					b.ReportMetric(respSize, "bytes/response")
				})
			}
		}
	}
}

func runVerifyBenchmark(b *testing.B, status ocsp.Status) {
	b.Helper()
	_, privateKey, err := mldsa44.GenerateKey(nil)

	if err != nil {
		log.Fatalf("creating key,  %v", err)
	}
	for _, numIssued := range issuedCounts {
		for _, revokedRatio := range RevokedRatios {
			tRevoked := int(math.Round(float64(numIssued) * revokedRatio))
			for _, numEpochs := range EpochCounts {
				name := fmt.Sprintf("issued=%d/revoked=%.0f%%/epochs=%d", numIssued, revokedRatio*100, numEpochs)
				b.Run(name, func(b *testing.B) {
					var lm *ocsp.Landmark
					date := time.Now()
					landmarks, target := buildMultiEpochLandmarks(b, numIssued, tRevoked, numEpochs, status)
					lm, err := getLandmarkFromBytes(target, landmarks)
					if err != nil {
						log.Fatalf("finding landmark from bytes")
					}
					// Unknown case (Since unknwon dont have a "real" date (since it benchmark), we simply take the date of the first lm
					if lm == nil {

						fakeFrequency := time.Hour
						fakeDate := landmarks[0].Date.Add(-time.Minute)

						lm, err = getLandmarkFromDate(fakeDate, fakeFrequency, landmarks)
						if err != nil {
							log.Fatalf("landmark from date")
						}
					}
					newestLandmark := landmarks[len(landmarks)-1]
					signedLandmark, err := newestLandmark.NewSignedHeadMLDSA(privateKey, crypto.SHA256, time.Second*30)
					if err != nil {
						b.Fatal(err)
					}

					resp, err := ocsp.NewResponse(target, lm, newestLandmark)
					if resp.Status != int8(status) {
						log.Fatalf("status mismatch %d != %d", resp.Status, int8(status))
					}
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						ok, err := ocsp.Verify(resp, signedLandmark, target, date)
						if err != nil {
							log.Fatalf("verifying response, %v", err)
						}
						if ok != true {
							log.Fatalf("bad response, ok = %t", ok)
						}
					}
				})
			}
		}
	}
}

// Server benchmarks
func BenchmarkGenerateProofSizeGood(b *testing.B) {
	runProofSizeBenchmark(b, ocsp.Good)
}
func BenchmarkGenerateProofSizeRevoked(b *testing.B) {
	runProofSizeBenchmark(b, ocsp.Revoked)

}
func BenchmarkGenerateProofSizeUnknown(b *testing.B) {
	runProofSizeBenchmark(b, ocsp.Unknown)

}

// Client benchmarks
func BenchmarkVerifyGood(b *testing.B) {
	runVerifyBenchmark(b, ocsp.Good)
}
func BenchmarkVerifyRevoked(b *testing.B) {
	runVerifyBenchmark(b, ocsp.Revoked)
}
func BenchmarkVerifyUnknown(b *testing.B) {
	runVerifyBenchmark(b, ocsp.Unknown)
}
func BenchmarkVerifyGoodForgedToRevoked(b *testing.B) {
	runVerifyBenchmark(b, ocsp.Unknown)
}
func BenchmarkVerifyGoodForgedToUnknown(b *testing.B) {
	runVerifyBenchmark(b, ocsp.Unknown)
}

// BenchClientVerify benchmarks the verify function, it does not include the signature verification

// Benchmark Revoked status proof growth based on Issued / Revoked / Epoch
// Benchmark Unknown staus proof growth based on Issued / Revoked / Epoch

// Benchmark Good status verify performance
// Benchmark Revoked status verify performance
// Benchmark Unknown status verify performance

// Benchmark "Bad" status verify performance?

// Benchmark Good response creation performance
// Benchmark Revoked response creation performance
// Benchmark Unknown response creation performance

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

func getLandmarkFromBytes(h []byte, landmarks []*ocsp.Landmark) (*ocsp.Landmark, error) {
	// For each landmark,
	for _, lm := range landmarks {
		if inTree, err := lm.CTree.Has(h); inTree {
			if err != nil {
				return nil, err
			}
			return lm, nil
		}
	}
	// Unknown status, Maybe, we here return based on date?
	return nil, nil
}

// GetLandmarkFromDate Finds a Landmark that covered the date.
// Idea: Each cert is issued during some time, placing them within one epoch.
//
//	intervalStart-> |---------| <- beforeEnd
func getLandmarkFromDate(date time.Time, frequency time.Duration, landmarks []*ocsp.Landmark) (*ocsp.Landmark, error) {

	s := slices.IndexFunc(landmarks, func(l *ocsp.Landmark) bool {
		intervalStart := l.Date.Add(-frequency)
		afterOrAtStart := !date.Before(intervalStart)
		beforeEnd := date.Before(l.Date)

		return afterOrAtStart && beforeEnd
	})

	if s == -1 {
		return nil, fmt.Errorf("no landmark found from date")
	}
	return landmarks[s], nil
}
