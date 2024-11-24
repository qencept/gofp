package dissector

import (
	"fmt"

	ethframe2 "github.com/qencept/gofp/pkg/eth/frame"
	"github.com/qencept/gofp/pkg/layers/l1"
	"github.com/qencept/gofp/pkg/layers/l2"
)

type Dissector struct {
	nextDissector NextDissector
}

type NextDissector map[ethframe2.EtherType]l2.Dissector

func New(nextDissectors NextDissector) *Dissector {
	return &Dissector{nextDissector: nextDissectors}
}

func (d *Dissector) Dissect(capture l1.Capture) error {
	header, err := ethframe2.ParseHeader(capture.Payload())
	if err != nil {
		return err
	}

	payload := capture.Payload()[ethframe2.HeaderLen:]

	next, ok := d.nextDissector[header.EtherType]
	if !ok {
		return fmt.Errorf("eth next not found for 0x%04x", header.EtherType)
	}

	frame := ethframe2.New(capture, header, payload)

	return next.Dissect(frame)
}
