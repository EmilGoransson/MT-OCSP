package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
func NewRootCertificateAndKey() (*CertObject, error) {
	pKey, err := NewKeyPair(2048)
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
	var ca = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Temp Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
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
func NewListRandomCertificates() ([][]byte, error) {
	var cList [][]byte
	for i := 0; i < 10; i++ {
		pKey, err := NewKeyPair(2048)
		if err != nil {
			return nil, err
		}
		cert, err := NewRandomCertificate(pKey, false)
		cList = append(cList, cert)
	}
	return cList, nil
}
