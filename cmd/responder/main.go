package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/responder"
	"merkle-ocsp/internal/util"
	"net/http"
	"time"
)

type server struct {
	pKey    *rsa.PrivateKey
	c       *responder.Controller
	signed  *ocsp.SignedLandmark
	done    chan bool
	chError chan error
}

func main() {
	port := ":8080"

	ch := make(chan error)
	done := make(chan bool)
	c, _ := responder.NewController()
	c.SetFrequency(1 * time.Second)
	key, _ := util.NewKeyPair(2048)
	s := &server{
		pKey:    key,
		c:       c,
		done:    done,
		chError: ch,
		signed:  nil,
	}

	http.HandleFunc("/ping", s.ping)
	http.HandleFunc("/start", s.start)
	http.HandleFunc("/stop", s.stop)
	http.HandleFunc("/cert/add", s.addCertificates)
	http.HandleFunc("/cert/revoke", s.addRevokedCertificates)
	http.HandleFunc("/test/cert/add", testAddCert)
	http.HandleFunc("/test/cert/revoke", testRevokeCert)
	http.HandleFunc("/test/proof/response", TestNewResponse)
	http.HandleFunc("/proof/response", s.NewResponse)

	http.HandleFunc("/landmark", s.getSignedLandmark)
	http.HandleFunc("/proof/hash", s.getLandmarkProof)
	fmt.Println("Listening at: ", "localhost:", port)
	/*


		srv := http.Server{
			Addr:         port,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		} */
	err := http.ListenAndServe(port, nil)
	if err != nil {
		panic(err)
	}

}
func (s *server) ping(w http.ResponseWriter, req *http.Request) {
	fmt.Println("ping req")
	_, err := w.Write([]byte("ping from server"))
	if err != nil {
		return
	}
}
func (s *server) stop(w http.ResponseWriter, req *http.Request) {
	fmt.Println("stop request")
	_, err := w.Write([]byte("Stopping ticker"))
	if err != nil {
		return
	}
	s.done <- false
}
func (s *server) start(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Start request")
	_, err := w.Write([]byte("Starting ticker"))
	if err != nil {
		return
	}
	s.c.StartPeriod(s.done, s.chError)
}
func (s *server) addCertificate(w http.ResponseWriter, r *http.Request) {
	fmt.Println("add-cert")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	fmt.Println("from cert add", body)
	if err != nil {
		http.Error(w, "bad data input", http.StatusBadRequest)
		return
	}
	s.c.AddCertificates([][]byte{body})
}
func (s *server) addCertificates(w http.ResponseWriter, r *http.Request) {
	fmt.Println("add-certs")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyStruct := struct {
		Certificates [][]byte
	}{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading data input", http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(body, &bodyStruct)
	if err != nil {
		http.Error(w, "bad data input", http.StatusBadRequest)
		return
	}
	log.Println("from cert add", body)
	s.c.AddCertificates(bodyStruct.Certificates)
}
func (s *server) addRevokedCertificates(w http.ResponseWriter, r *http.Request) {
	fmt.Println("rev-cert")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyStruct := struct {
		Certificates [][]byte
	}{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad data input", http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(body, &bodyStruct)
	if err != nil {
		http.Error(w, "bad data input", http.StatusBadRequest)
		return
	}
	s.c.AddRevokedCertificates(bodyStruct.Certificates)
}

// TODO: make it date based
func (s *server) getSignedLandmark(w http.ResponseWriter, r *http.Request) {
	if s.signed != nil {
		log.Println("signed-lm: ", s.signed)
	}
	signed, err := s.c.CurrentLandmark.NewSignedHead(s.pKey, crypto.SHA256)
	if err != nil {
		http.Error(w, "no landmark created", http.StatusInternalServerError)
		return
	}
	s.signed = signed
	err = json.NewEncoder(w).Encode(signed)
	if err != nil {
		return
	}

}
func testAddCert(w http.ResponseWriter, r *http.Request) {

	cert := []byte("issued-id-001")
	cert2 := []byte("revoked-id-002")
	certs := [][]byte{cert, cert2}

	body := struct {
		Certificates [][]byte
	}{
		Certificates: certs,
	}
	out, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	b := bytes.NewBuffer(out)
	response, err := http.Post("http://localhost:8080/cert/add", "application/json", b)
	if err != nil {
		return
	}
	defer response.Body.Close()
	fmt.Println("posted")
}

func testRevokeCert(w http.ResponseWriter, r *http.Request) {

	cert := []byte("revoked-id-002")

	body := struct {
		Certificates [][]byte `json:"certificates"`
	}{
		Certificates: [][]byte{cert},
	}
	out, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	b := bytes.NewBuffer(out)
	response, err := http.Post("http://localhost:8080/cert/revoke", "application/json", b)
	if err != nil {
		return
	}
	defer response.Body.Close()
	fmt.Println("revoked")
}

// getLandmarkProof returns the proof to the landmark for a specific hash
// Doesnt return anything for some reason
func (s *server) getLandmarkProof(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.c.CurrentLandmark == nil {
		http.Error(w, "no existing landmark", http.StatusMethodNotAllowed)
		return
	}
	// Check if the cert is in t
	var cert []byte
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading data input", http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(body, &cert)
	if err != nil {
		panic(err)
	}

	proof, err := s.c.CurrentLandmark.NewLandmarkProof(cert)

	if err != nil {
		http.Error(w, "error creating landmark proof", http.StatusInternalServerError)
		return
	}
	log.Println(proof)

	w.WriteHeader(http.StatusCreated)

	if err != nil {
		return
	}
}
func (s *server) NewResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.c.Landmarks) <= 0 {
		http.Error(w, "no landmarks issued", http.StatusInternalServerError)
		return
	}
	bodyStruct := struct {
		Certificate []byte `json:"certificates"`
	}{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "no data", http.StatusBadRequest)
	}
	err = json.Unmarshal(body, &bodyStruct)
	if err != nil {
		panic(err)
	}
	lm, err := s.c.GetLandmarkFromBytes(bodyStruct.Certificate)
	if err != nil {
		panic(err)
	}
	res, err := ocsp.NewResponse(bodyStruct.Certificate, lm)
	fmt.Println(res)
	retBody, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	_, err = w.Write(retBody)
	if err != nil {
		return
	}
	fmt.Println("Found Landmark: ", lm)
}
func TestNewResponse(w http.ResponseWriter, r *http.Request) {

	cert := []byte("revoked-id-002")

	body := struct {
		Certificate []byte `json:"certificates"`
	}{
		Certificate: cert,
	}
	out, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	lmBody := struct {
		Status    int8               `json:"Status"`
		Timestamp time.Time          `json:"Timestamp"`
		Proof     ocsp.LandmarkProof `json:"Proof"`
	}{}
	b := bytes.NewBuffer(out)
	response, err := http.Post("http://localhost:8080/proof/response", "application/json", b)
	if err != nil {
		return
	}
	if response.StatusCode == http.StatusOK {
		fmt.Println("200")
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(resBody, &lmBody)
		fmt.Println(lmBody)
	}

	//json.Unmarshal(response.Body, &body)
	//fmt.Println("revoked")
}
