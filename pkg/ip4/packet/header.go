package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

type IPProto uint8

const (
	IPProtoICMP4 IPProto = 1
	IPProtoTCP   IPProto = 6
	IPProtoUDP   IPProto = 17
)

const (
	MoreFragments = 1 << 0
	DontFragment  = 1 << 1
)

const HeaderMinLen = 20

type Header struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      uint16
	FragOffset uint16
	TTL        uint8
	Protocol   IPProto
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
}

func ParseHeader(data []uint8) (*Header, error) {
	if len(data) < HeaderMinLen {
		return nil, fmt.Errorf("ip4 length %d too small", len(data))
	}

	header := &Header{
		Version:    data[0] >> 4,
		IHL:        data[0] & 0x0F,
		TOS:        data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		Id:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      binary.BigEndian.Uint16(data[6:8]) >> 13,
		FragOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:        data[8],
		Protocol:   IPProto(data[9]),
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      data[12:16],
		DstIP:      data[16:20],
	}

	headerLength := int(header.IHL) * 4
	if header.Length < HeaderMinLen {
		return nil, fmt.Errorf("ip4 packet length %d too small", header.Length)
	}
	if headerLength < HeaderMinLen {
		return nil, fmt.Errorf("ip4 header length %d too small", header.IHL)
	}
	if headerLength > int(header.Length) {
		return nil, fmt.Errorf("ip header length %d greater than packet length %d", header.IHL, header.Length)
	}

	return header, nil
}
