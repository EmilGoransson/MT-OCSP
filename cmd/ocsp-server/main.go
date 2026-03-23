package ocsp_server

import "merkle-ocsp/internal/ocsp"

func main() {

}
func findLandmark(h []byte, store map[uint64]*ocsp.Landmark) (found *ocsp.Landmark) {
	for _, lm := range store {
		if has, _ := lm.Ctree.Has(h); has {
			found = lm
		}
	}
	return found
}
