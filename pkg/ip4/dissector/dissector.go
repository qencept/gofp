package dissector

import (
	"fmt"

	ip4packet2 "github.com/qencept/gofp/pkg/ip4/packet"
	"github.com/qencept/gofp/pkg/layers/l2"
	"github.com/qencept/gofp/pkg/layers/l3"
)

type Dissector struct {
	nextDissectors NextDissectors
}

type NextDissectors map[ip4packet2.IPProto]l3.Dissector

func New(nextDissectors NextDissectors) *Dissector {
	return &Dissector{nextDissectors: nextDissectors}
}

func (d *Dissector) Dissect(frame l2.Frame) error {
	header, err := ip4packet2.ParseHeader(frame.Payload())
	if err != nil {
		return err
	}

	payload := frame.Payload()[header.IHL*4:]

	//!!! ip4 defragmentation
	if header.FragOffset != 0 || header.Flags&ip4packet2.MoreFragments != 0 {
		return fmt.Errorf("ip4 fragment offset %v flags %v", header.FragOffset, header.Flags)
	}

	next, ok := d.nextDissectors[header.Protocol]
	if !ok {
		return fmt.Errorf("ip4 nextparser not found for 0x%04x", header.Protocol)
	}

	packet := ip4packet2.New(frame, header, payload)

	return next.Dissect(packet)
}
