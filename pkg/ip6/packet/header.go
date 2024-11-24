package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

type NextHeader int

const (
	NextHeaderTCP NextHeader = 6
	NextHeaderUDP NextHeader = 17
)

const HeaderLen = 40

type Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   NextHeader
	HopLimit     uint8
	Src          net.IP
	Dst          net.IP
}

func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderLen {
		return nil, fmt.Errorf("ip4 length %d too small", len(data))
	}
	h := &Header{
		Version:      data[0] >> 4,
		TrafficClass: data[0]&0x0f<<4 | data[1]>>4,
		FlowLabel:    uint32(data[1]&0x0f)<<16 | uint32(data[2])<<8 | uint32(data[3]),
		PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   NextHeader(data[6]),
		HopLimit:     data[7],
	}
	h.Src = make(net.IP, net.IPv6len)
	copy(h.Src, data[8:24])
	h.Dst = make(net.IP, net.IPv6len)
	copy(h.Dst, data[24:40])
	return h, nil
}
