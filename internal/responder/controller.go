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
	fmt.Println("Issued certs: ", c.IssuedCertsNext)
	fmt.Println("Revoked certs: ", c.RevokedCertsNext)
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
func (c *Controller) StartPeriod(done chan bool, ch chan<- error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	freq := c.Frequency

	fmt.Println("--Started period!--", freq)

	ticker := time.NewTicker(freq)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-done:
				{
					return
				}
			case _ = <-ticker.C:
				{
					err := c.updateController()
					if err != nil && ch != nil {
						ch <- fmt.Errorf("when updating, %v", err)
					}
				}
			}
		}
	}()
}
func (c *Controller) updateController() error {
	fmt.Println("Updating!")
	issued, revoked := c.Certificates.refresh()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.CurrentLandmark != nil {
		c.CurrentLandmark.CTree.RevSMT = c.CurrentLandmark.CTree.RevSMT.Freeze()
	}

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

// GetLandmarkFromDate Finds a Landmark that covered the date.
// Idea: Each cert is issued during some time, placing them within one epoch.
// Validate that it works
func (c *Controller) GetLandmarkFromDate(date time.Time) (*ocsp.Landmark, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := slices.IndexFunc(c.Landmarks, func(l *ocsp.Landmark) bool {
		intervalStart := l.Date.Add(-c.Frequency)
		afterOrAtStart := !date.Before(intervalStart)
		beforeEnd := date.Before(l.Date)

		return afterOrAtStart && beforeEnd
	})

	if s == -1 {
		return nil, nil
	}
	return c.Landmarks[s], nil
}

// GetLandmarkFromBytes is a Naive and slow solution
func (c *Controller) GetLandmarkFromBytes(h []byte) (*ocsp.Landmark, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// For each landmark,
	for _, lm := range c.Landmarks {
		if inTree, err := lm.CTree.Has(h); inTree {
			if err != nil {
				return nil, err
			}
			return lm, nil
		}
	}
	// Unknown status, Maybe, we here return based on date?
	return nil, nil
}

// Consider moving proof here so that responder logic moves via controller always responder -> Controller -> proof or w/e
func (c *Controller) NewProof() {

}
