package frame

import (
	"github.com/qencept/gofp/pkg/layers/l1"
)

type Frame struct {
	baseL1  l1.Capture
	header  *Header
	payload []uint8
}

func New(basel1 l1.Capture, header *Header, payload []uint8) *Frame {
	return &Frame{
		baseL1:  basel1,
		header:  header,
		payload: payload,
	}
}

func (p *Frame) BaseL1() l1.Capture {
	return p.baseL1
}

func (p *Frame) DstHwAddr() []uint8 {
	return p.header.DstMAC
}

func (p *Frame) SrcHwAddr() []uint8 {
	return p.header.SrcMAC
}

func (p *Frame) Payload() []uint8 {
	return p.payload
}
