package ocsp

import (
	"encoding/binary"
	"time"
)

func MarshalTimestamp(t time.Time) []byte {
	b := make([]byte, 8)
	tInt := t.UTC().UnixNano()
	binary.BigEndian.PutUint64(b, uint64(tInt))
	return b
}
