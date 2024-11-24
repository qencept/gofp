package dissector

import (
	"fmt"

	packet2 "github.com/qencept/gofp/pkg/ip6/packet"
	"github.com/qencept/gofp/pkg/layers/l2"
	"github.com/qencept/gofp/pkg/layers/l3"
)

type Dissector struct {
	nextDissectors NextDissectors
}

type NextDissectors map[packet2.NextHeader]l3.Dissector

func New(nextDissectors NextDissectors) *Dissector {
	return &Dissector{nextDissectors: nextDissectors}
}

func (d *Dissector) Dissect(frame l2.Frame) error {
	header, err := packet2.ParseHeader(frame.Payload())
	if err != nil {
		return err
	}

	payload := frame.Payload()[40:]

	//!!! ip6 defragmentation

	next, ok := d.nextDissectors[packet2.NextHeader(header.NextHeader)]
	if !ok {
		return fmt.Errorf("ip6 nextparser not found for 0x%04x", header.NextHeader)
	}

	packet := packet2.New(frame, header, payload)

	return next.Dissect(packet)
}
