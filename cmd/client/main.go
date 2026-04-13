package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"math/big"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/pb"
	"net/http"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"google.golang.org/protobuf/proto"
)

const ip = "http://localhost:8080"

func hashSerial(serial []byte) []byte {
	h := sha256.Sum256(serial)
	return h[:]
}

func main() {
	demo()
}

func demo() {
	// Creates 3 certificates
	// Random big-int (serial), & create "valid" issue time
	t := time.Now()
	serialGood := big.NewInt(1111)
	dateGood := t

	serialRevoked := big.NewInt(2222)
	dateRevoked := t

	serialUnknown := big.NewInt(3333)
	dateUnknown := t

	// Add the Certificates to the responder
	postCertificates([][]byte{serialGood.Bytes(), serialRevoked.Bytes()})
	postRevokedCertificates([][]byte{serialRevoked.Bytes()})

	// Wait for the server to add the "issued certificates"
	fmt.Println("Waiting 20s to simulate delay")
	time.Sleep(20 * time.Second)

	// Gets the latest landmark that includes the previously posted certificates (covers them all)
	lm, err := TestGetSignedLandmark()

	if err != nil {
		panic(err)
	}
	// Fetches status of a certificate via OCSP
	responseGood := pbPostGetResponseProof(serialGood, dateGood)
	responseRevoked := pbPostGetResponseProof(serialRevoked, dateRevoked)
	responseUnknown := pbPostGetResponseProof(serialUnknown, dateUnknown)
	// To check bad timestamp
	//r.Proof.CombinedProof.IssueDate = time.Now()

	// Fetch the servers public key
	key, _ := getPublicKeyMLDSA()
	fmt.Println("key")
	// ValidateLandmark the signature using the servers public key
	valid := ValidateLandmarkMLDSA(lm, key)
	fmt.Printf("[Valid Landmark] Validating signature, Valid: %t\n", valid)

	fmt.Println("=====================================")
	fmt.Println("========== VALID RESPONSES ==========")
	fmt.Println("=====================================")

	// Verifies the proof in
	verifyGood, err := ocsp.Verify(responseGood, lm, hashSerial(serialGood.Bytes()), dateGood)
	fmt.Printf("[Valid Response status=%s]  Proof valid:  %t\n", ocsp.Status(responseGood.Status), verifyGood)
	if err != nil {
		log.Println(err)
	}
	verifyRevoked, err := ocsp.Verify(responseRevoked, lm, hashSerial(serialRevoked.Bytes()), dateRevoked)
	fmt.Printf("[Valid Response status=%s]  Proof valid:  %t\n", ocsp.Status(responseRevoked.Status), verifyRevoked)
	if err != nil {
		log.Println(err)
	}
	verifyUnknown, err := ocsp.Verify(responseUnknown, lm, hashSerial(serialUnknown.Bytes()), dateUnknown)
	fmt.Printf("[Valid Response status=%s]  Proof valid:  %t\n", ocsp.Status(responseUnknown.Status), verifyUnknown)
	if err != nil {
		log.Println(err)
	}

	// Modify the responses and see if the proof is deemed false
	fmt.Println("=====================================")
	fmt.Println("======== MODIFIED RESPONSES =========")
	fmt.Println("=====================================")

	responseGood.Status = ocsp.Revoked
	responseRevoked.Status = ocsp.Good
	responseUnknown.Status = ocsp.Good

	// Verify the modified proof again
	verifyGoodModified, err := ocsp.Verify(responseGood, lm, hashSerial(serialGood.Bytes()), dateGood)
	fmt.Printf("[Modified Response] status=%s: Proof valid:  %t\n", ocsp.Status(responseGood.Status), verifyGoodModified)
	if err != nil {
		log.Println(err)
	}
	verifyRevokedModified, err := ocsp.Verify(responseRevoked, lm, hashSerial(serialRevoked.Bytes()), dateRevoked)
	fmt.Printf("[Modified Response] status=%s: Proof valid:  %t\n", ocsp.Status(responseRevoked.Status), verifyRevokedModified)
	if err != nil {
		log.Println(err)
	}
	verifyUnknownModified, err := ocsp.Verify(responseUnknown, lm, hashSerial(serialUnknown.Bytes()), dateUnknown)
	fmt.Printf("[Modified Response] status=%s: Proof valid:  %t\n", ocsp.Status(responseUnknown.Status), verifyUnknownModified)
	if err != nil {
		log.Println(err)
	}
}

// ValidateLandmark validates a signed landmark against a public key
func ValidateLandmark(l *ocsp.SignedLandmark, k *rsa.PublicKey) (bool, error) {
	if l == nil || k == nil {
		return false, fmt.Errorf("input cant be nil")
	}
	h := sha256.New()
	logSize := make([]byte, 8)
	binary.BigEndian.PutUint64(logSize, l.LogSize)
	date := ocsp.MarshalTimestamp(l.Date)
	freqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(freqBytes, uint64(l.Frequency))
	// Structure of the SignedLandmark
	h.Write(l.LogRoot)
	h.Write(logSize)
	h.Write(freqBytes)
	h.Write(date)
	s := h.Sum(nil)
	err := rsa.VerifyPKCS1v15(k, crypto.SHA256, s, l.SignedHashData)
	if err != nil {
		return false, err
	}
	return true, nil

}
func ValidateLandmarkMLDSA(l *ocsp.SignedLandmark, k *mldsa44.PublicKey) bool {
	h := sha256.New()
	logSize := make([]byte, 8)
	binary.BigEndian.PutUint64(logSize, l.LogSize)
	date := ocsp.MarshalTimestamp(l.Date)
	freqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(freqBytes, uint64(l.Frequency))
	// Structure of the SignedLandmark
	h.Write(l.LogRoot)
	h.Write(logSize)
	h.Write(freqBytes)
	h.Write(date)
	s := h.Sum(nil)
	return mldsa44.Verify(k, s, nil, l.SignedHashData)
}

func TestGetSignedLandmark() (*ocsp.SignedLandmark, error) {
	response, err := http.Get(ip + "/landmark/mldsa44")
	if err != nil {
		return nil, fmt.Errorf("getting response, %v", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status not 200")
	}
	var lm ocsp.SignedLandmark
	dec := gob.NewDecoder(response.Body)
	err = dec.Decode(&lm)
	if err != nil {
		return nil, fmt.Errorf("reading body, %v", err)
	}
	return &lm, nil
}

func postGetResponseProof(serial *big.Int, date time.Time) *ocsp.Response {
	body := ocsp.Request{
		SerialBytes: serial.Bytes(),
		Date:        date,
	}
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(body)
	if err != nil {
		panic(err)
	}
	var lmBody ocsp.Response
	response, err := http.Post(ip+"/proof/response", "application/octet-stream", &buffer)
	if err != nil {
		return nil
	}
	if response.StatusCode == http.StatusOK {
		dec := gob.NewDecoder(response.Body)
		err := dec.Decode(&lmBody)
		if err != nil {
			panic(err)
		}
		return &lmBody
	}
	msg, _ := io.ReadAll(response.Body)
	log.Fatalf("got status, %s, %s ", response.Status, msg)
	return nil
}
func pbPostGetResponseProof(serial *big.Int, date time.Time) *ocsp.Response {
	body := ocsp.Request{
		SerialBytes: serial.Bytes(),
		Date:        date,
	}
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(body)
	if err != nil {
		panic(err)
	}
	response, err := http.Post(ip+"/proof/response", "application/protobuf", &buffer)
	if err != nil {
		return nil
	}
	if response.StatusCode == http.StatusOK {
		/*	dec := gob.NewDecoder(response.Body)
			err := dec.Decode(&lmBody)
		*/
		b, err := io.ReadAll(response.Body)
		if err != nil {
			log.Panicf("recoding data, %v", err)
		}
		var ocspPB pb.Response
		err = proto.Unmarshal(b, &ocspPB)
		ocspResponse, err := pb.ProtoToResponse(&ocspPB)
		if err != nil {
			log.Fatalf("going from proto to ocsp.response, %v", err)
		}
		return ocspResponse
	}
	msg, _ := io.ReadAll(response.Body)
	log.Fatalf("got status, %s, %s ", response.Status, msg)
	return nil
}

func postCertificates(c [][]byte) {

	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(c)
	if err != nil {
		panic(err)
	}
	response, err := http.Post(ip+"/cert/add", "application/octet-stream", &buffer)
	if err != nil {
		return
	}
	defer response.Body.Close()
}
func postRevokedCertificates(c [][]byte) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(c)
	if err != nil {
		panic(err)
	}
	response, err := http.Post(ip+"/cert/revoke", "application/octet-stream", &buffer)
	if err != nil {
		return
	}
	defer response.Body.Close()
}
func getPublicKey() (*rsa.PublicKey, error) {
	req, err := http.Get(ip + "/key")
	if err != nil {
		return nil, err
	}
	dec := gob.NewDecoder(req.Body)
	var pub = rsa.PublicKey{}
	err = dec.Decode(&pub)
	if err != nil {
		return nil, err
	}
	return &pub, nil
}
func getPublicKeyMLDSA() (*mldsa44.PublicKey, error) {
	req, err := http.Get(ip + "/key/mldsa44")
	if err != nil {
		return nil, err
	}
	dec := gob.NewDecoder(req.Body)
	var pub = mldsa44.PublicKey{}
	err = dec.Decode(&pub)
	if err != nil {
		return nil, err
	}
	return &pub, nil
}
