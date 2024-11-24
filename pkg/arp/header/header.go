package header

import (
	"encoding/binary"
	"fmt"
)

const (
	TypeEthernet     = 1
	ProtocolIP4      = 0x0800
	OperationRequest = 1
	OperationReply   = 2
)

const HeaderMinLen = 28

type Header struct {
	Type               uint16
	Protocol           uint16
	HwAddrSize         uint8
	ProtocolAddrSize   uint8
	Operation          uint16
	SenderHwAddress    []byte
	SenderProtocolAddr []byte
	TargetHwAddr       []byte
	TargetProtocolAddr []byte
}

func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderMinLen {
		return nil, fmt.Errorf("arp parse length %d too small", len(data))
	}

	header := &Header{
		Type:               binary.BigEndian.Uint16(data[0:2]),
		Protocol:           binary.BigEndian.Uint16(data[2:4]),
		HwAddrSize:         data[4],
		ProtocolAddrSize:   data[5],
		Operation:          binary.BigEndian.Uint16(data[6:8]),
		SenderHwAddress:    data[8:14],
		SenderProtocolAddr: data[14:18],
		TargetHwAddr:       data[18:24],
		TargetProtocolAddr: data[24:28],
	}

	return header, nil
}
