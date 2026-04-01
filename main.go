package main

func main() {
	demo()
}

func demo() {
	/*	revokedCerts1 := [][]byte{
			[]byte("revoked-id-1"),
			[]byte("revoked-id-11"),
		}
		issuedCerts1 := [][]byte{
			[]byte("issued-id-001"),
			[]byte("issued-id-002"),
			[]byte("issued-id-003"),
			[]byte("issued-id-006"),
			[]byte("revoked-id-1"),
			[]byte("revoked-id-11"),
		}
		issuedCerts2 := [][]byte{
			[]byte("revoked-id-111"),
		}
		issuedCerts3 := [][]byte{
			[]byte("issued-id-333"),
		}
		revokedCerts2 := [][]byte{
			[]byte("revoked-id-111"),
		}
		// First epoch
		_, _ = util.NewKeyPair(2048)
		controller, _ := responder.NewController()
		controller.SetFrequency(2 * time.Second)
		controller.AddCertificates(issuedCerts1)
		controller.AddRevokedCertificates(revokedCerts1)
		ch := make(chan error)
		done := make(chan bool)
		controller.StartPeriod(done, ch)

		err := <-ch
		if err != nil {
			log.Fatalf("error in batch-handler %v", err)
		}
		for _, leaf := range controller.CurrentLandmark.CTree.IssuedMT.Leaves {
			fmt.Println(string(leaf))
		}
		fmt.Println("--Done--")

		// 2nd Epoch
		controller.AddCertificates(issuedCerts2)
		controller.AddRevokedCertificates(revokedCerts2)
		controller.StartPeriod(ch, done)

		controller.AddCertificates(issuedCerts3)

		err = <-ch
		if err != nil {
			log.Fatalf("error in batch-handler %v", err)
		}
		for _, leaf := range controller.CurrentLandmark.CTree.IssuedMT.Leaves {
			fmt.Println(string(leaf))
		}
		fmt.Println("--Done--")

		controller.StartPeriod(ch)
		err = <-ch
		if err != nil {
			log.Fatalf("error in batch-handler %v", err)
		}
	*/
	/*

		revokedCerts := [][]byte{
			[]byte("revoked-id-1"),
			[]byte("revoked-id-11"),
			[]byte("revoked-id-111"),
			[]byte("revoked-id-1111"),
			[]byte("revoked-id-11111"),
			[]byte("revoked-id-111111"),
			[]byte("revoked-id-1111111"),
			[]byte("revoked-id-11111111"),
			[]byte("revoked-id-1111111111"),
			[]byte("revoked-id-11111111111"),
			[]byte("revoked-id-111111111111"),
		}
		issuedCerts := [][]byte{
			[]byte("issued-id-001"),
			[]byte("issued-id-002"),
			[]byte("issued-id-003"),
			[]byte("issued-id-006"),
			[]byte("revoked-id-1"),
			[]byte("revoked-id-11"),
			[]byte("revoked-id-111"),
			[]byte("revoked-id-1111"),
			[]byte("revoked-id-11111"),
			[]byte("revoked-id-111111"),
			[]byte("revoked-id-1111111"),
			[]byte("revoked-id-11111111"),
			[]byte("revoked-id-1111111111"),
			[]byte("revoked-id-11111111111"),
			[]byte("revoked-id-111111111111"),
		}
		keys, _ := util.NewKeyPair(2048)

		controller, _ := util.NewController(keys)
		controller.SetFrequency(20 * time.Second)
		controller.AddCertificates(issuedCerts)
		controller.AddRevokedCertificates(revokedCerts)

		c := make(chan string)
		controller.StartPeriod(c)
		x := <-c
		fmt.Println("debug")

		fmt.Println(x)



			// CA
			//combinedTreeStore := make(map[int64]Combined)
			log, _ := tree.NewLog()
			revocationTree := tree.NewSparse()
			caKey, _ := util.NewRootCertificateAndKey(2048)
			initTree, _ := tree.NewCombined(issuedCerts, revokedCerts, revocationTree)

			//_, _ = initTree.AddBulkRevocationToTree(revokedCerts)
			//Store the combinedTree
			//combinedTreeStore[0] = *initTree
			_ = log.AppendToLog(initTree.Root)
			// Generate landmark to publish
			landmark, _ := ocsp.NewLandmark(log, initTree)
			// Sign the lm
			signed, _ := landmark.NewSignedHead(caKey.PKey, crypto.SHA256)

			// Signed sent to client

			// From client perspective
			// 1. Verifies the signature
			// Calculate the hash
			hasher := crypto.SHA256.New()
			// Converts treesize to []byte
			treeSizeHash := make([]byte, 8)
			size := signed.LogSize
			binary.BigEndian.PutUint64(treeSizeHash, size)
			timeHash, err := signed.Date.MarshalBinary()
			if err != nil {
				_ = fmt.Errorf("marshaling time, %v", err)
			}
			hasher.Write(signed.LogRoot)
			hasher.Write(treeSizeHash)
			hasher.Write(timeHash)
			checksum := hasher.Sum(nil)

			pubKey := caKey.PKey.PublicKey

			err = rsa.VerifyPKCS1v15(&pubKey, crypto.SHA256, checksum, signed.SignedHashData)
			if err != nil {
				_ = fmt.Errorf("verifying data, %v", err)
			}
			// If no error -> Signature is valid -> We can trust the data.

			// Wants to validate a util, t.ex revokedCerts[0]
			// Sent to server (revokedCerts[0] OR ID?)
			certToCheck := []byte("UNKNOWN CERT TEST")
			// Makes a request -> OCSPResponder

			// OCSP responder
			receivedCert := certToCheck
			fmt.Println(receivedCert)

			// Checks its status: e.g: ValidateCert(receivedCert) // should prov be in its own folder /verify
			// Need function to find landmark index and the combined Tree
			// Find correct combinedTree using date? => Use combinedTree.root to find correct landmark
			// lets say we find correct combinedTree initTree
			fetchedTree := initTree
			fetchedLog := log
			// NewLandmarkProof currently takes a landmark, however, it only uses combinedTree & the issue log to generate proof.
			// Lets say that we find combinedTree & issue log
			notReallyLandmark := landmark

			// We now either hash the util or use its ID (how does it OCSP & also smaller)
			// Generate OCSP response
			fmt.Println(fetchedTree)
			fmt.Println(fetchedLog)
			res, _ := ocsp.newResponse(certToCheck, notReallyLandmark)

			// to be encoded and sent to the client

			// Client receives the response, and should validate it
			// ValidateProof() should:
			// 1. Validate the proof of the combinedProof and make sure it is valid together with status, store the root of the calculated tree
			// 2. Validate that the previously calculated root exists in the log using signed.logRoot
			/*
				h := sha256.New()
				h.Write(certToCheck)
				hCert := h.Sum(nil)

			hCert := certToCheck

			// Move to Verify .go or something
			// Client should import
			fmt.Println("Status: ", res.Status)
			switch res.Status {
			// status = good doesn't work as it should...
			case ocsp.Good:
				block, _ := tree.ByteToDataBlock(certToCheck)
				verify, err := mt.Verify(block, res.Proof.CombinedProof.IssueProof, res.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
				verifyRev := smt.VerifyProof(*res.Proof.CombinedProof.RevProof, res.Proof.CombinedProof.RevRoot, hCert, []byte{}, sha256.New())
				//debug, testProof is not the same as res.Proof.CombinedProof.RevProof, why?
				fmt.Println("In issuance tree:", verify, err)
				fmt.Println("Not in revocation tree:", verifyRev)

			case ocsp.Revoked:
				block, _ := tree.ByteToDataBlock(certToCheck)
				verify, err := mt.Verify(block, res.Proof.CombinedProof.IssueProof, res.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
				verifyRev := smt.VerifyProof(*res.Proof.CombinedProof.RevProof, res.Proof.CombinedProof.RevRoot, hCert, hCert, sha256.New())
				fmt.Println("In issuance tree:", verify, err)
				fmt.Println("In revocation tree:", verifyRev)

			case ocsp.Unknown:
				fmt.Println("status = unknown: todo, implement this")
				verify, err := tree.ValidateExclusion(certToCheck, res.Proof.CombinedProof.NonIssueProof, res.Proof.CombinedProof.IssueRoot, tree.DefaultMerkleConfig)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println("Validation of exclusion proof: ", verify, err)
			}
			if err != nil {
				return
			}
	*/
}
