package l2

import (
	"github.com/qencept/gofp/pkg/layers/l1"
)

type Frame interface {
	BaseL1() l1.Capture
	DstHwAddr() []uint8
	SrcHwAddr() []uint8
	Payload() []uint8
}

type Dissector interface {
	Dissect(Frame) error
}
