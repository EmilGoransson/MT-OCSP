package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/responder"
	"merkle-ocsp/internal/util"
	"net/http"
	"time"
)

type server struct {
	Key     *rsa.PrivateKey
	c       *responder.Controller
	latest  *ocsp.Landmark
	signed  *ocsp.SignedLandmark
	done    chan bool
	chError chan error
}

func main() {
	port := ":8080"
	ch := make(chan error)
	done := make(chan bool)
	c, _ := responder.NewController()
	c.SetFrequency(15 * time.Second)
	key, _ := util.NewKeyPair(2048)
	s := &server{
		Key:     key,
		c:       c,
		done:    done,
		chError: ch,
		signed:  nil,
		latest:  nil,
	}

	http.HandleFunc("/ping", s.ping)
	http.HandleFunc("/start", s.start)
	http.HandleFunc("/stop", s.stop)
	http.HandleFunc("/cert/add", s.addCertificates)
	http.HandleFunc("/cert/revoke", s.addRevokedCertificates)
	http.HandleFunc("/test/cert/add", testAddCert)
	http.HandleFunc("/test/cert/revoke", testRevokeCert)
	http.HandleFunc("/test/proof/response", testNewResponse)
	http.HandleFunc("/proof/response", s.newResponse)
	http.HandleFunc("/key", s.key)

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
func (s *server) key(w http.ResponseWriter, req *http.Request) {
	fmt.Println("key")
	enc := gob.NewEncoder(w)
	err := enc.Encode(s.Key.PublicKey)
	if err != nil {
		return
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
	var c []byte
	enc := gob.NewDecoder(r.Body)
	err := enc.Decode(&c)
	if err != nil {
		http.Error(w, "bad data input", http.StatusBadRequest)
		return
	}
	s.c.AddCertificates([][]byte{c})
}
func (s *server) addCertificates(w http.ResponseWriter, r *http.Request) {
	fmt.Println("add-certs")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var certificates [][]byte

	enc := gob.NewDecoder(r.Body)
	err := enc.Decode(&certificates)

	if err != nil {
		http.Error(w, "reading data input", http.StatusBadRequest)
		return
	}
	log.Println("from cert add", certificates)
	s.c.AddCertificates(certificates)
}
func (s *server) addRevokedCertificates(w http.ResponseWriter, r *http.Request) {
	fmt.Println("rev-cert")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var certificates [][]byte

	enc := gob.NewDecoder(r.Body)
	err := enc.Decode(&certificates)
	if err != nil {
		http.Error(w, "bad data input", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "bad data input", http.StatusBadRequest)
		return
	}
	s.c.AddRevokedCertificates(certificates)
}

// TODO: make it date based
func (s *server) getSignedLandmark(w http.ResponseWriter, r *http.Request) {
	if s.signed != nil {
		log.Println("signed-lm: ", s.signed)
	}
	signed, err := s.c.CurrentLandmark.NewSignedHead(s.Key, crypto.SHA256, s.c.Frequency)
	if err != nil {
		http.Error(w, "no landmark created", http.StatusInternalServerError)
		return
	}
	s.signed = signed
	enc := gob.NewEncoder(w)
	err = enc.Encode(signed)
	if err != nil {
		http.Error(w, "encoding lm failed", http.StatusInternalServerError)
	}
	if err != nil {
		return
	}
}
func testAddCert(w http.ResponseWriter, r *http.Request) {
	serial := big.NewInt(1111)
	serialBytes := serial.Bytes()

	serial2 := big.NewInt(2222)
	serialBytes2 := serial2.Bytes()
	/*
		cert := append([]byte("issued-id-001"))
		cert2 := []byte("revoked-id-002")
	*/
	certs := [][]byte{serialBytes, serialBytes2}
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(certs)
	if err != nil {
		panic(err)
	}
	response, err := http.Post("http://localhost:8080/cert/add", "application/octet-stream", &buffer)
	if err != nil {
		return
	}
	defer response.Body.Close()
	fmt.Println("posted")
}

func testRevokeCert(w http.ResponseWriter, r *http.Request) {

	serial := big.NewInt(1111)
	serialBytes := serial.Bytes()

	certs := [][]byte{serialBytes}
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(certs)

	if err != nil {
		panic(err)
	}
	response, err := http.Post("http://localhost:8080/cert/revoke", "application/octet-stream", &buffer)
	if err != nil {
		return
	}
	defer response.Body.Close()
	fmt.Println("revoked")
}

// getLandmarkProof returns the proof to the landmark for a specific hash
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
	dec := gob.NewDecoder(r.Body)
	err := dec.Decode(&cert)
	if err != nil {
		http.Error(w, "reading data input", http.StatusBadRequest)
		return
	}
	// TODO: make it so that the controller issues the proof (server should always call the controller)
	proof, err := s.c.CurrentLandmark.NewLandmarkProof(cert, s.c.CurrentLandmark)

	if err != nil {
		http.Error(w, "error creating landmark proof", http.StatusInternalServerError)
		return
	}
	log.Println(proof)

	w.WriteHeader(http.StatusCreated)
}
func (s *server) newResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.c.Landmarks) <= 0 {
		http.Error(w, "no landmarks issued", http.StatusInternalServerError)
		return
	}
	var bodyStruct ocsp.Request
	dec := gob.NewDecoder(r.Body)
	err := dec.Decode(&bodyStruct)
	if err != nil {
		http.Error(w, "no data", http.StatusBadRequest)
		return
	}
	if err != nil {
		panic(err)
	}
	// If the cert has not been added to a landmark yet
	if s.c.CurrentLandmark.Date.Before(bodyStruct.Date) {
		msg := fmt.Sprintf("cert not added to log yet. Last landmark: %s, Cert issuance: %s",
			s.c.CurrentLandmark.Date, bodyStruct.Date)

		http.Error(w, msg, http.StatusNotFound)
		return
	}

	lm, err := s.c.GetLandmarkFromBytes(bodyStruct.Certificate)
	if err != nil {
		log.Fatalf("finding the landmark %v", err)
	}

	// If lm = nil, we try getting it from date (unknown status)
	if lm == nil {
		lm, err = s.c.GetLandmarkFromDate(bodyStruct.Date)
		if err != nil {
			log.Fatalf("finding lm using date")
			return
		}
	}
	res, err := ocsp.NewResponse(bodyStruct.Certificate, lm, s.c.CurrentLandmark)
	fmt.Println(res)
	enc := gob.NewEncoder(w)
	err = enc.Encode(res)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	fmt.Println("Found Landmark: ", lm)
}
func testNewResponse(w http.ResponseWriter, r *http.Request) {

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
	lmBody := ocsp.Response{}
	b := bytes.NewBuffer(out)
	response, err := http.Post("http://localhost:8080/proof/response", "application/octet-stream", b)
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
