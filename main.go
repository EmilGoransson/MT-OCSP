package main

import (
	"fmt"
)

func main() {
	// Manual testing

	toCheck := []byte("Cert-9")

	fmt.Println("checking", string(toCheck))
	log, _ := NewAppendLog()
	_ = log.appendToLog([]byte("Cert-1"))
	_ = log.appendToLog([]byte("Cert-4"))
	_ = log.appendToLog([]byte("Cert-2"))
	_ = log.appendToLog([]byte("Cert-3"))
	_ = log.appendToLog([]byte("Cert-4"))
	_ = log.appendToLog([]byte("Cert-4"))
	_ = log.appendToLog([]byte("Cert-4"))
	_ = log.appendToLog([]byte("Cert-10"))

	index, err := log.findIndex(toCheck)
	if err != nil {
		panic(err)
	}

	testproof, err := log.newProof(index)
	if err != nil {
		panic(err)
	}
	fmt.Println("testproof: ", testproof)
	fmt.Println(log.getSize())
	verified, err := log.VerifyProof(toCheck, testproof)
	if err != nil {
		panic(err)
	}
	fmt.Println(verified)
}
