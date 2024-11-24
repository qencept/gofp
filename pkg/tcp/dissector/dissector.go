package dissector

import (
	"github.com/qencept/gofp/pkg/layers/l3"
	"github.com/qencept/gofp/pkg/layers/l4"
	tcpsegment2 "github.com/qencept/gofp/pkg/tcp/segment"
)

type Dissector struct {
	assembler     Assembler
	nextDissector l4.Dissector
}

type Assembler interface {
	Assemble(segment *tcpsegment2.Segment) (l4.Stream, error)
}

func New(assembler Assembler, netxDissector l4.Dissector) *Dissector {
	return &Dissector{
		assembler:     assembler,
		nextDissector: netxDissector,
	}
}

func (d *Dissector) Dissect(packet l3.Packet) error {
	header, payload, err := tcpsegment2.Decode(packet.Payload())
	if err != nil {
		return err
	}

	segment := tcpsegment2.New(packet, header, payload)

	assemblyUpdate, err := d.assembler.Assemble(segment)
	if err != nil {
		return err
	}

	return d.nextDissector.Dissect(assemblyUpdate)
}
