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

func (p *Packet) Payload() []uint8 {
	return p.payload
}

func (p *Packet) SrcIP() net.IP {
	return p.header.SrcIP
}

func (p *Packet) DstIP() net.IP {
	return p.header.DstIP
}

func (p *Packet) TTL() uint8 {
	return p.header.TTL
}
