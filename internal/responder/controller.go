package responder

import (
	"fmt"
	"merkle-ocsp/internal/ocsp"
	"merkle-ocsp/internal/tree"
	"slices"
	"sync"
	"time"
)

type Controller struct {
	Certificates    *CertificatesNext
	Log             *tree.Log
	Revocation      *tree.Sparse
	Landmarks       []*ocsp.Landmark
	CurrentLandmark *ocsp.Landmark
	Frequency       time.Duration
	mu              sync.Mutex
}

type CertificatesNext struct {
	IssuedCertsNext  [][]byte
	RevokedCertsNext [][]byte
	mu               sync.Mutex
}

func NewController() (*Controller, error) {
	log, err := tree.NewLog()
	if err != nil {
		return nil, err
	}

	return &Controller{
		Certificates: &CertificatesNext{},
		Log:          log,
		Revocation:   tree.NewSparse(),
	}, nil
}

// AddCertificates queues certificates for the next period.
func (c *Controller) AddCertificates(certs [][]byte) {
	c.Certificates.addIssued(certs)
}

// AddRevokedCertificates queues revoked certificates for the next period.
func (c *Controller) AddRevokedCertificates(certs [][]byte) {
	c.Certificates.addRevoked(certs)
}

func (c *CertificatesNext) addIssued(certs [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cert := range certs {
		c.IssuedCertsNext = append(c.IssuedCertsNext, cert)
	}
}

func (c *CertificatesNext) addRevoked(certs [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cert := range certs {
		c.RevokedCertsNext = append(c.RevokedCertsNext, cert)
	}
}

func (c *CertificatesNext) refresh() (issued [][]byte, revoked [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	issued = c.IssuedCertsNext
	revoked = c.RevokedCertsNext
	c.IssuedCertsNext = nil
	c.RevokedCertsNext = nil
	return issued, revoked
}

func (c *Controller) SetFrequency(t time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Frequency = t
}
func (c *Controller) StartPeriod(ch chan<- error) {
	c.mu.Lock()
	freq := c.Frequency
	c.mu.Unlock()

	fmt.Println("--Started period!--", freq)
	time.AfterFunc(freq, func() {
		err := c.UpdateController()
		if ch != nil {
			ch <- err
		}
	})
}
func (c *Controller) UpdateController() error {
	fmt.Println("Updating!")
	issued, revoked := c.Certificates.refresh()

	c.mu.Lock()
	defer c.mu.Unlock()

	newCombined, err := tree.NewCombined(issued, revoked, c.Revocation)
	if err != nil {
		return err
	}
	newLandmark, err := ocsp.NewLandmark(c.Log, newCombined)
	if err != nil {
		return err
	}

	c.Landmarks = append(c.Landmarks, newLandmark)
	c.CurrentLandmark = newLandmark
	return nil
}

// GetCombinedTreeFromDate Finds a Landmark that covered the date.
// Idea: Each cert is issued during some time, placing them within one epoch.
func (c *Controller) GetCombinedTreeFromDate(h []byte, date time.Time) (*ocsp.Landmark, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := slices.IndexFunc(c.Landmarks, func(l *ocsp.Landmark) bool {
		isBefore := l.Date.Add(-c.Frequency).Before(date)
		return l.Date.After(date) && isBefore
	})
	// Unknown status
	if s == -1 {
		return nil, nil
	}
	return c.Landmarks[s], nil
}
