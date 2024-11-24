package dissector

import (
	icmp4header "github.com/qencept/gofp/pkg/icmp4/header"
	"github.com/qencept/gofp/pkg/layers/l3"
)

type Dissector struct {
}

func New() *Dissector {
	return &Dissector{}
}

func (d *Dissector) Dissect(packet l3.Packet) error {
	header, err := icmp4header.ParseHeader(packet.Payload())
	if err != nil {
		return err
	}

	payload := packet.Payload()[icmp4header.HeaderSize:]

	// palace for icmp4 handler
	_, _ = header, payload

	return nil
}
