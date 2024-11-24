package packet

import (
	"net"

	"github.com/qencept/gofp/pkg/layers/l2"
)

type Packet struct {
	baseL2  l2.Frame
	header  *Header
	payload []uint8
}

func New(baseL2 l2.Frame, header *Header, payload []uint8) *Packet {
	return &Packet{
		baseL2:  baseL2,
		header:  header,
		payload: payload,
	}
}

func (p *Packet) BaseL2() l2.Frame {
	return p.baseL2
}

func (p *Packet) DstIP() net.IP {
	return p.header.Dst
}

func (p *Packet) SrcIP() net.IP {
	return p.header.Src
}

func (p *Packet) TTL() uint8 {
	return p.header.HopLimit
}

func (p *Packet) Payload() []uint8 {
	return p.payload
}
