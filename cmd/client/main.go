package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"merkle-ocsp/internal/ocsp"
	"net/http"
	"time"
)

func main() {
	//key, _ := util.NewKeyPair(2048)
	// (Fake Cert)
	// Random big-int (serial)
	serial := big.NewInt(1111)
	serialBytes := serial.Bytes()
	date := time.Now()
	//cert2, err := util.NewRandomCertificate(key, false)
	// wait for cert to be "valid" time-wise (depends on frequency in responder)
	time.Sleep(20 * time.Second)
	lm, err := TestGetSignedLandmark()
	// Should Validate that the data matches the hash
	if err != nil {
		panic(err)
	}
	/*
		 serial, err := util.ExtractSerial(cert2)

		date, err := util.ExtractDate(cert2)
		if err != nil {
			panic(err)
		} */
	// TODO: Remove the serialBytes, only serial is needed
	r := TestNewResponse(serialBytes, serial, date)
	// To check bad timestamp
	//r.Proof.CombinedProof.IssueDate = time.Now()

	// Fetch the servers public key
	req, err := http.Get("http://localhost:8080/key")
	if err != nil {
		panic(err)
	}
	// Decodes the public bytes send via tcp
	dec := gob.NewDecoder(req.Body)
	var pub = rsa.PublicKey{}
	err = dec.Decode(&pub)
	if err != nil {
		return
	}
	// Validate the signature
	valid, err := Validate(lm, &pub)
	fmt.Printf("signature valid: , %t\n", valid)
	if err != nil {
		panic(err)
	}
	// Verifies the proof in r=response
	verify, err := ocsp.Verify(r, lm, serial.Bytes(), date)
	fmt.Printf("Validating returned proof for status=%s: Proof valid:  %t\n", ocsp.Status(r.Status), verify)
	fmt.Println(verify)
	if err != nil {
		panic(err)
	}

}

// Validate validates a signed landmark against a public key
func Validate(l *ocsp.SignedLandmark, k *rsa.PublicKey) (bool, error) {
	if l == nil || k == nil {
		return false, fmt.Errorf("input cant be nil")
	}
	h := sha256.New()
	logSize := make([]byte, 8)
	binary.BigEndian.PutUint64(logSize, l.LogSize)
	date, err := l.Date.MarshalBinary()
	if err != nil {
		return false, nil
	}
	freqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(freqBytes, uint64(l.Frequency))
	// Structure of the SignedLandmark
	h.Write(l.LogRoot)
	h.Write(logSize)
	h.Write(freqBytes)
	h.Write(date)
	s := h.Sum(nil)
	err = rsa.VerifyPKCS1v15(k, crypto.SHA256, s, l.SignedHashData)
	if err != nil {
		return false, err
	}
	return true, nil

}

func TestGetSignedLandmark() (*ocsp.SignedLandmark, error) {

	response, err := http.Get("http://localhost:8080/landmark")
	if err != nil {
		return nil, fmt.Errorf("getting response, %v", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status not 200")
	}
	if err != nil {
		return nil, fmt.Errorf("getting response%v", err)
	}
	lm := ocsp.SignedLandmark{}
	resBody, err := io.ReadAll(response.Body)

	if err != nil {
		return nil, fmt.Errorf("reading body, %v", err)
	}
	res := json.Unmarshal(resBody, &lm)
	fmt.Println(res)
	return &lm, nil
}

func TestNewResponse(b []byte, serial *big.Int, date time.Time) *ocsp.Response {
	body := struct {
		Certificate []byte    `json:"certificates"`
		Serial      *big.Int  `json:"serial"`
		Date        time.Time `json:"issue-date"`
	}{
		Certificate: b,
		Serial:      serial,
		Date:        date,
	}
	out, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	lmBody := ocsp.Response{}
	buff := bytes.NewBuffer(out)
	response, err := http.Post("http://localhost:8080/proof/response", "application/json", buff)
	if err != nil {
		return nil
	}
	if response.StatusCode == http.StatusOK {
		fmt.Println("200")
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(resBody, &lmBody)
		fmt.Println(lmBody)
		return &lmBody
	}
	msg, _ := io.ReadAll(response.Body)
	log.Fatalf("got status, %s, %s ", response.Status, msg)
	return nil
}
func FetchKey() {

}
