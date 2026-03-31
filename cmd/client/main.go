package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/util"
	"net/http"
	"time"
)

func main() {
	key, _ := util.NewKeyPair(2048)
	// cert := []byte("issued-id-001")
	cert2, err := util.NewRandomCertificate(key, false)
	// wait for cert to be "valid" time-wise (depends on frequency in responder)
	time.Sleep(20 * time.Second)
	lm, err := TestGetSignedLandmark()
	if err != nil {
		panic(err)
	}
	serial, err := util.ExtractSerial(cert2)
	fmt.Println(serial)
	date, err := util.ExtractDate(cert2)
	fmt.Println(date)
	if err != nil {
		panic(err)
	}
	r := TestNewResponse(serial.Bytes(), serial, date)
	verify, err := ocsp.Verify(r, lm, serial.Bytes(), date)
	fmt.Printf("Validating returned proof for status=%s: Proof valid:  %t\n", ocsp.Status(r.Status), verify)
	fmt.Println(verify)
	if err != nil {
		panic(err)
	}

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
