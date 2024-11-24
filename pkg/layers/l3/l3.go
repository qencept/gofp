package l3

import (
	"net"

	"github.com/qencept/gofp/pkg/layers/l2"
)

type Packet interface {
	BaseL2() l2.Frame
	DstIP() net.IP
	SrcIP() net.IP
	TTL() uint8
	Payload() []uint8
}

type Dissector interface {
	Dissect(Packet) error
}
