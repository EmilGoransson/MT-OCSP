package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type CertObject struct {
	PKey *rsa.PrivateKey
	cert []byte
}

func HashCert(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
func HashList(list [][]byte) [][]byte {
	for index, data := range list {
		list[index] = HashCert(data)
	}
	return list
}

func ExtractSerial(b []byte) (*big.Int, error) {
	c, err := x509.ParseCertificates(b)
	if err != nil {
		return nil, fmt.Errorf("converting byte to cert")
	}
	if len(c) <= 0 {
		return nil, fmt.Errorf("len 0 or shorter")
	}
	return c[0].SerialNumber, nil

}
func ExtractDate(b []byte) (time.Time, error) {
	c, err := x509.ParseCertificates(b)
	if err != nil {
		return time.Time{}, fmt.Errorf("converting byte to cert")
	}
	if len(c) <= 0 {
		return time.Time{}, fmt.Errorf("len 0 or shorter")
	}
	return c[0].NotBefore, nil
}

func NewKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
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
	time := time.Now()
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
		NotBefore:             time,
		NotAfter:              time.AddDate(0, 0, 200),
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
