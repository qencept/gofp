package header

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	TypeEchoReply   = 0
	TypeEchoRequest = 8
)

const HeaderSize = 16

type Header struct {
	Type      uint8
	Code      uint8
	Checksum  uint16
	Id        uint16
	Seq       uint16
	Timestamp time.Time
}

func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("icmp parse length %d too small", len(data))
	}

	header := &Header{
		Type:      data[0],
		Code:      data[1],
		Checksum:  binary.BigEndian.Uint16(data[2:4]),
		Id:        binary.BigEndian.Uint16(data[4:6]),
		Seq:       binary.BigEndian.Uint16(data[6:8]),
		Timestamp: time.Unix(int64(binary.BigEndian.Uint32(data[8:12])), 1000*int64(binary.BigEndian.Uint32(data[12:16]))),
	}

	return header, nil
}
