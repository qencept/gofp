package segment

import (
	"encoding/binary"
	"fmt"
)

const (
	OptionEndList       = 0
	OptionNop           = 1
	OptionMSS           = 2
	OptionWindowScale   = 3
	OptionSACKPermitted = 4
	OptionSACK          = 5
	OptionTimestamps    = 8
)

const HeaderMinLen = 20

type Header struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNumber  int
	AckNumber  int
	DataOffset uint8
	FIN        bool
	SYN        bool
	RST        bool
	PSH        bool
	ACK        bool
	URG        bool
	ECE        bool
	CWR        bool
	NS         bool
	Window     uint16
	Checksum   uint16
	Urgent     uint16

	OptionKinds       []uint8
	OptionMSS         uint16
	OptionWindowScale uint8
}

func Decode(data []uint8) (*Header, []uint8, error) {
	if len(data) < HeaderMinLen {
		return nil, nil, fmt.Errorf("tcp length %d too small", len(data))
	}

	header := &Header{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNumber:  int(binary.BigEndian.Uint32(data[4:8])),
		AckNumber:  int(binary.BigEndian.Uint32(data[8:12])),
		DataOffset: data[12] >> 4,
		FIN:        data[13]&0x01 != 0,
		SYN:        data[13]&0x02 != 0,
		RST:        data[13]&0x04 != 0,
		PSH:        data[13]&0x08 != 0,
		ACK:        data[13]&0x10 != 0,
		URG:        data[13]&0x20 != 0,
		ECE:        data[13]&0x40 != 0,
		CWR:        data[13]&0x80 != 0,
		NS:         data[12]&0x01 != 0,
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}

	payloadOffset := int(header.DataOffset) * 4
	if payloadOffset < HeaderMinLen {
		return nil, nil, fmt.Errorf("tcp data offset %d too small", payloadOffset)
	}
	if payloadOffset > len(data) {
		return nil, nil, fmt.Errorf("tcp data offset greater than packet length")
	}

	payload := data[payloadOffset:]
	data = data[HeaderMinLen:payloadOffset]

	for len(data) > 0 {
		kind := data[0]
		length := 1
		if kind != OptionNop && kind != OptionEndList {
			if len(data) < 2 {
				return nil, nil, fmt.Errorf("tcp option length %d too small", len(data))
			}
			length = int(data[1])
			if length < 2 {
				return nil, nil, fmt.Errorf("tcp option length %d too small", length)
			}
			if length > len(data) {
				return nil, nil, fmt.Errorf("tcp option length %d exceeds remaining %d uint8s", length, len(data))
			}
			switch kind {
			case OptionMSS:
				header.OptionMSS = binary.BigEndian.Uint16(data[2:length])
			case OptionWindowScale:
				header.OptionWindowScale = data[2]
			}
		}
		header.OptionKinds = append(header.OptionKinds, kind)
		data = data[length:]
	}

	return header, payload, nil
}
