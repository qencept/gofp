package segment

import (
	"github.com/qencept/gofp/pkg/layers/l3"
)

type Segment struct {
	baseL3  l3.Packet
	header  *Header
	payload []uint8
}

func New(baseL3 l3.Packet, header *Header, payload []uint8) *Segment {
	return &Segment{
		baseL3:  baseL3,
		header:  header,
		payload: payload,
	}
}

func (s *Segment) BaseL3() l3.Packet {
	return s.baseL3
}

func (s *Segment) Header() *Header {
	return s.header
}

func (s *Segment) Payload() []uint8 {
	return s.payload
}
