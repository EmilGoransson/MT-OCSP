package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type CertObject struct {
	pKey *rsa.PrivateKey
	cert []byte
}

func NewKeyPair(bits int) (*rsa.PrivateKey, error) {
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return caPrivateKey, nil
}
func NewRootCertificateAndKey(keyLength int) (*CertObject, error) {
	if keyLength < 2048 {
		return nil, errors.New("bad key length")
	}
	pKey, err := NewKeyPair(keyLength)
	if err != nil {
		return nil, err
	}
	cert, err := NewRandomCertificate(pKey, true)
	if err != nil {
		return nil, err
	}
	return &CertObject{pKey, cert}, nil
}
func NewRandomCertificate(pkey *rsa.PrivateKey, isCa bool) ([]byte, error) {
	// Specify algorithm
	r, _ := rand.Int(rand.Reader, big.NewInt(100))
	var ca = &x509.Certificate{
		SerialNumber: r,
		Subject: pkix.Name{
			Organization:  []string{randomString(10)},
			Country:       []string{randomString(10)},
			Province:      []string{randomString(10)},
			Locality:      []string{randomString(10)},
			StreetAddress: []string{randomString(10)},
			PostalCode:    []string{randomString(5)},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  isCa,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &pkey.PublicKey, pkey)
	if err != nil {
		return caBytes, err
	}
	return caBytes, nil
}
func randomString(length int) string {
	b := make([]byte, length+2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[2 : length+2]
}
func NewListRandomCertificatesWithKey(n int, pKey *rsa.PrivateKey) ([][]byte, error) {
	var cList [][]byte
	for i := 0; i < n; i++ {
		cert, err := NewRandomCertificate(pKey, false)
		if err != nil {
			return nil, err
		}
		cList = append(cList, cert)
	}
	return cList, nil
}
