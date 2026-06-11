package benchmark

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
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

var issuedCounts = []int{10, 100, 100_0, 100_00, 100_000, 100_000_0, 100_000_00, 100_000_000}

// How many % of certs that are revoked
var RevokedRatios = []float64{0, 0.01, 0.05, 0.1}

var EpochCounts = []int{1, 10, 100, 1000}

func buildMultiEpochLandmarks(t testing.TB, totalIssued, totalRevoked, numEpochs int, status ocsp.Status) ([]*ocsp.Landmark, []byte) {
	t.Helper()
	l, err := tree.NewLog()
	if err != nil {
		t.Fatalf("creating new log: %v", err)
	}

	allIssuedHashes := make([][]byte, totalIssued)
	for i := range allIssuedHashes {
		allIssuedHashes[i] = hashUint64(uint64(i + 1))
	}

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
		startIssue, endIssue := epochRange(totalIssued, numEpochs, j)
		startRev, endRev := epochRange(totalRevoked, numEpochs, j)

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
		if len(allRevokedHashes) == 0 {
			t.Fatalf("revoked status benchmark needs at least one revoked certificate")
		}
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
			tRevoked := revokedCount(numIssued, revokedRatio)
			for _, numEpochs := range EpochCounts {
				name := benchmarkCaseName(numIssued, tRevoked, revokedRatio, numEpochs)
				if status == ocsp.Revoked && tRevoked == 0 {
					b.Run(name, func(b *testing.B) { skipZeroRevokedStatus(b, status, tRevoked) })
					continue
				}

				landmarks, target := buildMultiEpochLandmarks(b, numIssued, tRevoked, numEpochs, status)
				issueLandmark, err := getLandmarkFromBytes(target, landmarks)
				if err != nil {
					b.Fatalf("finding hash in landmarks: %v", err)
				}
				if issueLandmark == nil {
					fakeFrequency := time.Hour
					fakeDate := landmarks[0].Date.Add(-time.Minute)
					issueLandmark, err = getLandmarkFromDate(fakeDate, fakeFrequency, landmarks)
					if err != nil {
						b.Fatalf("landmark from date: %v", err)
					}
				}
				newestLandmark := landmarks[len(landmarks)-1]
				sampleResp, err := ocsp.NewResponse(target, issueLandmark, newestLandmark)
				if err != nil {
					b.Fatal(err)
				}
				if sampleResp.Status != int8(status) {
					b.Fatalf("status mismatch %d != %d", sampleResp.Status, int8(status))
				}
				samplePbResp := responseToProto(b, sampleResp)
				respSize := float64(protoSize(b, samplePbResp))

				b.Run(name, func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, err = ocsp.NewResponse(target, issueLandmark, newestLandmark)
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
			tRevoked := revokedCount(numIssued, revokedRatio)
			for _, numEpochs := range EpochCounts {
				name := benchmarkCaseName(numIssued, tRevoked, revokedRatio, numEpochs)
				if status == ocsp.Revoked && tRevoked == 0 {
					b.Run(name, func(b *testing.B) { skipZeroRevokedStatus(b, status, tRevoked) })
					continue
				}

				landmarks, target := buildMultiEpochLandmarks(b, numIssued, tRevoked, numEpochs, status)
				lm, err := getLandmarkFromBytes(target, landmarks)
				if err != nil {
					b.Fatalf("finding landmark from bytes: %v", err)
				}
				if lm == nil {
					fakeFrequency := time.Hour * 4
					fakeDate := landmarks[0].Date.Add(-time.Minute)
					lm, err = getLandmarkFromDate(fakeDate, fakeFrequency, landmarks)
					if err != nil {
						b.Fatalf("landmark from date: %v", err)
					}
				}
				newestLandmark := landmarks[len(landmarks)-1]

				b.Run(name, func(b *testing.B) {
					signedLandmark, err := newestLandmark.NewSignedHeadMLDSA(privateKey, crypto.SHA256, time.Second*30)
					if err != nil {
						b.Fatal(err)
					}
					resp, err := ocsp.NewResponse(target, lm, newestLandmark)
					if err != nil {
						b.Fatal(err)
					}
					if resp.Status != int8(status) {
						b.Fatalf("status mismatch %d != %d", resp.Status, int8(status))
					}
					date := lm.CTree.Date.Add(-time.Second)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						ok, err := ocsp.Verify(resp, signedLandmark, target, date)
						if err != nil {
							b.Fatalf("verifying response, %v", err)
						}
						if !ok {
							b.Fatalf("bad response, ok = %t", ok)
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

var msgSizes = []int{
	16,
	32,
	64,
	128,
	256,
	512,
}

func BenchmarkSignMLDSA44(b *testing.B) {
	_, priv, _ := mldsa44.GenerateKey(nil)
	sig := make([]byte, mldsa44.SignatureSize)

	for _, size := range msgSizes {
		msg := make([]byte, size)
		b.Run(fmt.Sprintf("msg=%dB", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := mldsa44.SignTo(priv, msg, nil, true, sig); err != nil {
					b.Fatalf("signing failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkVerifyMLDSA44(b *testing.B) {
	pub, priv, _ := mldsa44.GenerateKey(nil)
	sig := make([]byte, mldsa44.SignatureSize)

	for _, size := range msgSizes {
		msg := make([]byte, size)
		if err := mldsa44.SignTo(priv, msg, nil, true, sig); err != nil {
			b.Fatalf("setup signing failed: %v", err)
		}
		b.Run(fmt.Sprintf("msg=%dB", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mldsa44.Verify(pub, msg, nil, sig)
			}
		})
	}
}

func BenchmarkLandmarkSize(b *testing.B) {
	_, privateKey, _ := mldsa44.GenerateKey(nil)
	for _, numIssued := range issuedCounts {
		for _, revokedRatio := range RevokedRatios {
			tRevoked := revokedCount(numIssued, revokedRatio)
			for _, numEpochs := range EpochCounts {
				name := benchmarkCaseName(numIssued, tRevoked, revokedRatio, numEpochs)
				lm, _ := buildMultiEpochLandmarks(b, numIssued, tRevoked, numEpochs, ocsp.Good)

				b.Run(name, func(b *testing.B) {
					b.ResetTimer()
					var respSize float64
					for i := 0; i < b.N; i++ {
						signedLm, err := lm[0].NewSignedHeadMLDSA(privateKey, crypto.SHA256, time.Hour)
						var buf bytes.Buffer
						enc := gob.NewEncoder(&buf)
						err = enc.Encode(signedLm)
						if err != nil {
							fmt.Errorf("encoding")
						}
						respSize = float64(buf.Len())
					}
					b.ReportMetric(respSize, "bytes/response")
				})
			}
		}
	}
}

func hashUint64(v uint64) []byte {
	var serial [8]byte
	binary.BigEndian.PutUint64(serial[:], v)
	sum := sha256.Sum256(serial[:])
	return sum[:]
}

func revokedCount(numIssued int, revokedRatio float64) int {
	return int(math.Round(float64(numIssued) * revokedRatio))
}

func benchmarkCaseName(numIssued, numRevoked int, revokedRatio float64, numEpochs int) string {
	return fmt.Sprintf("issued=%d/revoked=%.3g%%/revoked_count=%d/epochs=%d", numIssued, revokedRatio*100, numRevoked, numEpochs)
}

func skipZeroRevokedStatus(b *testing.B, status ocsp.Status, numRevoked int) {
	b.Helper()
	if status == ocsp.Revoked && numRevoked == 0 {
		b.Skip("revoked status requires at least one revoked certificate")
	}
}

func epochRange(total, numEpochs, epoch int) (int, int) {
	return epoch * total / numEpochs, (epoch + 1) * total / numEpochs
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
