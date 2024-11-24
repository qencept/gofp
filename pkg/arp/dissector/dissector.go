package dissector

import (
	arpheader "github.com/qencept/gofp/pkg/arp/header"
	"github.com/qencept/gofp/pkg/layers/l2"
)

type Dissector struct {
}

func New() *Dissector {
	return &Dissector{}
}

func (d *Dissector) Dissect(frame l2.Frame) error {
	header, err := arpheader.ParseHeader(frame.Payload())
	if err != nil {
		return err
	}

	// palace for arp handler
	_ = header

	return nil
}
