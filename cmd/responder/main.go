package main

func main() {
	/*


		revokedCerts1 := [][]byte{
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
		revokedCerts2 := [][]byte{
			[]byte("revoked-id-111"),
		}
		// First epoch
		_, _ = util.NewKeyPair(2048)

		controller, _ := NewController()
		controller.SetFrequency(2 * time.Second)
		controller.AddCertificates(issuedCerts1)
		controller.AddRevokedCertificates(revokedCerts1)
		ch := make(chan string)
		controller.StartPeriod(ch)

		x := <-ch
		fmt.Println(x)
		for _, leaf := range controller.CurrentLandmark.CTree.IssuedMT.Leaves {
			fmt.Println(string(leaf))
		}

		// 2nd Epoch
		controller.AddCertificates(issuedCerts2)
		controller.AddRevokedCertificates(revokedCerts2)
		controller.StartPeriod(ch)

		x = <-ch
		fmt.Println(x)
		for _, leaf := range controller.CurrentLandmark.CTree.IssuedMT.Leaves {
			fmt.Println(string(leaf))
		}

	*/
}

/*


func findLandmark(h []byte, store map[uint64]*ocsp.Landmark) (found *ocsp.Landmark) {
	for _, lm := range store {
		if has, _ := lm.CTree.Has(h); has {
			found = lm
		}
	}
	return found


}*/
