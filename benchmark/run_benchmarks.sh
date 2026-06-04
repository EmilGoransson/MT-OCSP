#!/usr/bin/env bash
set -e

go test  -v -bench=BenchmarkGenerateProofSizeGood    -benchmem -count=10 | tee benchmark_GenerateProofSizeGood10x.txt
go test  -v -bench=BenchmarkGenerateProofSizeRevoked  -benchmem -count=10 | tee benchmark_GenerateProofSizeRevoked10x.txt
go test  -v -bench=BenchmarkGenerateProofSizeUnknown  -benchmem -count=10 | tee benchmark_GenerateProofSizeUnknown10x.txt

go test -v -bench=BenchmarkVerifyGood -benchmem -count=10 | tee benchmark_VerifyGood10x.txt
go test -v -bench=BenchmarkVerifyRevoked -benchmem -count=10 | tee benchmark_VerifyRevoked10x.txt
go test -v -bench=BenchmarkVerifyUnknown -benchmem -count=10 | tee benchmark_VerifyUnknown10x.txt
