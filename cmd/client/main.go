package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"merkle-ocsp/internal/ocsp"
	"net/http"
)

func main() {
	cert := []byte("revoked-id-002")
	lm, err := TestGetSignedLandmark()
	if err != nil {
		panic(err)
	}
	r := TestNewResponse(cert)
	verify, err := ocsp.Verify(r, lm, cert)
	if err != nil {
		panic(err)
	}
	fmt.Println(verify)
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

func TestNewResponse(b []byte) *ocsp.Response {
	body := struct {
		Certificate []byte `json:"certificates"`
	}{
		Certificate: b,
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
	return nil
}
