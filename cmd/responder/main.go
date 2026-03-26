package main

import (
	"crypto/rsa"
	"fmt"
	"merkle-ocsp/internal/responder"
	"merkle-ocsp/internal/util"
	"net/http"
	"time"
)

type server struct {
	pKey    *rsa.PrivateKey
	c       *responder.Controller
	done    chan bool
	chError chan error
}

func main() {
	port := ":8080"

	ch := make(chan error)
	done := make(chan bool)
	c, _ := responder.NewController()
	c.SetFrequency(5 * time.Second)
	key, _ := util.NewKeyPair(2048)
	s := &server{
		pKey:    key,
		c:       c,
		done:    done,
		chError: ch,
	}

	http.HandleFunc("/ping", s.ping)
	http.HandleFunc("/start", s.Start)
	http.HandleFunc("/stop", s.Stop)
	fmt.Println("Listening at: ", "localhost:", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		panic(err)
	}

}
func (s server) ping(w http.ResponseWriter, req *http.Request) {
	fmt.Println("ping req")
	_, err := w.Write([]byte("ping from server"))
	if err != nil {
		return
	}
}
func (s server) Stop(w http.ResponseWriter, req *http.Request) {
	fmt.Println("stop request")
	_, err := w.Write([]byte("Stopping ticker"))
	if err != nil {
		return
	}
	s.done <- false
}
func (s server) Start(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Start request")
	_, err := w.Write([]byte("Starting ticker"))
	if err != nil {
		return
	}
	s.c.StartPeriod(s.done, s.chError)
}
