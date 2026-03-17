package main

import (
	"fmt"

	"github.com/transparency-dev/merkle/rfc6962"
)

func main() {
	log, _ := NewAppendLog()
	_ = log.appendToLog([]byte("Cert-1"))
	_ = log.appendToLog([]byte("Cert-2"))
	_ = log.appendToLog([]byte("Cert-3"))
	_ = log.appendToLog([]byte("Cert-4"))
	_ = log.appendToLog([]byte("Cert-5"))
	testproof, err := log.newProof(4)
	if err != nil {
		panic(err)
	}
	fmt.Println("testproof: ", testproof)
	fmt.Println(log.getSize())
	verified, err := log.VerifyProof(rfc6962.DefaultHasher.HashLeaf([]byte("Cert-5")), testproof)
	if err != nil {
		panic(err)
	}
	fmt.Println(verified)
}
