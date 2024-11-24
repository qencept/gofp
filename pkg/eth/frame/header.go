package frame

import (
	"encoding/binary"
	"fmt"
)

type EtherType uint16

const EtherTypeARP EtherType = 0x0806
const EtherTypeIPv4 EtherType = 0x0800
const EtherTypeIPv6 EtherType = 0x86DD

const HeaderLen = 14

type Header struct {
	DstMAC    []uint8
	SrcMAC    []uint8
	EtherType EtherType
}

func ParseHeader(data []uint8) (*Header, error) {
	if len(data) < HeaderLen {
		return nil, fmt.Errorf("eth length %v too small", len(data))
	}

	header := &Header{
		DstMAC:    data[0:6],
		SrcMAC:    data[6:12],
		EtherType: EtherType(binary.BigEndian.Uint16(data[12:14])),
	}

	return header, nil
}
