package ocsp

import (
	"merkle-ocsp/internal/cert"
	"merkle-ocsp/internal/tree"
	"testing"
)

func TestNewMerkleResponse(t *testing.T) {
	key, err := cert.NewKeyPair(2048)
	certs, err := cert.NewListRandomCertificatesWithKey(10, key)
	certs = cert.HashList(certs)
	if err != nil {
		t.Fatalf("Failed to generate certs: %v", err)
	}
	// ca, _ := NewRootCertificateAndKey(2048)
	log, _ := tree.NewLog()
	revokedTree := tree.NewSparse()
	cTree, _ := tree.NewCombinedTree(certs, nil, revokedTree)
	_ = log.AppendToLog(cTree.Root)
	lm1, _ := NewLandmark(log, cTree)

	t.Run("returns response for issued cert", func(t *testing.T) {
		resp, err := NewResponse(certs[0], lm1)
		if err != nil {
			t.Fatalf("NewResponse() returned error: %v", err)
		}
		if resp == nil {
			t.Fatal("Expected non-nil response")
		}
		if resp.Proof == nil {
			t.Error("Expected proof to be set in response")
		}
		if resp.timestamp.IsZero() {
			t.Error("Expected timestamp to be set")
		}
	})

	t.Run("response status is Good for issued non-revoked cert", func(t *testing.T) {
		resp, err := NewResponse(certs[1], lm1)
		if err != nil {
			t.Fatalf("NewResponse() returned error: %v", err)
		}
		if resp.Status != Good {
			t.Errorf("Expected status Good (%d), got %d", Good, resp.Status)
		}
	})

	t.Run("response status is Revoked for revoked cert", func(t *testing.T) {
		_, err := cTree.AddRevocationToTree(certs[2])
		if err != nil {
			t.Fatalf("Failed to revoke cert: %v", err)
		}
		resp, err := NewResponse(certs[2], lm1)
		if err != nil {
			t.Fatalf("NewResponse() returned error: %v", err)
		}
		if resp.Status != Revoked {
			t.Errorf("Expected status Revoked (%d), got %d", Revoked, resp.Status)
		}
	})

	// Not implemented yet. Proof for unknown status not implemented
	/*
		t.Run("response status is Unknown for cert not in tree", func(t *testing.T) {
			unknownCert := []byte("cert-never-issued")
			resp, err := NewResponse(unknownCert, lm1)
			if err != nil {
				t.Fatalf("NewResponse() returned error: %v", err)
			}
			if resp.Status != Unknown {
				t.Errorf("Expected status Unknown (%d), got %d", Unknown, resp.Status)
			}
		}) */
}

func TestGetStatus(t *testing.T) {
	key, err := cert.NewKeyPair(2048)
	certs, err := cert.NewListRandomCertificatesWithKey(10, key)
	revTree := tree.NewSparse()
	if err != nil {
		t.Fatalf("Failed to generate certs: %v", err)
	}
	tree, err := tree.NewCombinedTree(certs, nil, revTree)
	if err != nil {
		t.Fatalf("Failed to create combined tree: %v", err)
	}

	t.Run("Good - issued and not revoked", func(t *testing.T) {
		status, err := getStatus(tree, certs[0])
		if err != nil {
			t.Fatalf("getStatus() returned error: %v", err)
		}
		if status != Good {
			t.Errorf("Expected Good (%d), got %d", Good, status)
		}
	})

	t.Run("Revoked - issued and revoked", func(t *testing.T) {
		_, err := tree.AddRevocationToTree(certs[1])
		if err != nil {
			t.Fatalf("Failed to revoke cert: %v", err)
		}
		status, err := getStatus(tree, certs[1])
		if err != nil {
			t.Fatalf("getStatus() returned error: %v", err)
		}
		if status != Revoked {
			t.Errorf("Expected Revoked (%d), got %d", Revoked, status)
		}
	})

	t.Run("Unknown - never issued", func(t *testing.T) {
		status, err := getStatus(tree, []byte("not-in-tree"))
		if err != nil {
			t.Fatalf("getStatus() returned error: %v", err)
		}
		if status != Unknown {
			t.Errorf("Expected Unknown (%d), got %d", Unknown, status)
		}
	})

	t.Run("status changes after revocation", func(t *testing.T) {
		statusBefore, err := getStatus(tree, certs[2])
		if err != nil {
			t.Fatalf("getStatus() before revocation returned error: %v", err)
		}
		if statusBefore != Good {
			t.Errorf("Expected Good before revocation, got %d", statusBefore)
		}

		_, err = tree.AddRevocationToTree(certs[2])
		if err != nil {
			t.Fatalf("Failed to revoke cert: %v", err)
		}

		statusAfter, err := getStatus(tree, certs[2])
		if err != nil {
			t.Fatalf("getStatus() after revocation returned error: %v", err)
		}
		if statusAfter != Revoked {
			t.Errorf("Expected Revoked after revocation, got %d", statusAfter)
		}
	})

	t.Run("revoked-but-unknown - revoked but never issued", func(t *testing.T) {
		ghostCert := []byte("revoked-but-never-issued")
		_, err := tree.AddRevocationToTree(ghostCert)
		if err != nil {
			t.Fatalf("Failed to add ghost revocation: %v", err)
		}
		// isIssued check comes first in getStatus, so this should return Unknown
		status, err := getStatus(tree, ghostCert)
		if err != nil {
			t.Fatalf("getStatus() returned error: %v", err)
		}
		if status != Unknown {
			t.Errorf("Expected Unknown for revoked-but-never-issued cert, got %d", status)
		}
	})
}
