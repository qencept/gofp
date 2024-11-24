package record

import (
	"errors"
)

type Record struct {
	Type          int
	LegacyVersion int
	Length        int
}

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

const (
	RecordHandshake = 22
)

var ErrNotEnoughData = errors.New("not enough data")
