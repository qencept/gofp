package ja4t

import (
	"fmt"

	"github.com/qencept/gofp/pkg/tcp/segment"
)

type JA4T struct {
	fp string
}

func New(header *segment.Header) *JA4T {
	var optionKinds string
	for _, kind := range header.OptionKinds {
		if len(optionKinds) > 0 {
			optionKinds += "-"
		}
		optionKinds += fmt.Sprintf("%d", kind)
	}
	fp := fmt.Sprintf("%v_%v_%v_%v", header.Window, optionKinds, header.OptionMSS, header.OptionWindowScale)
	return &JA4T{fp: fp}
}

func (ja4t *JA4T) String() string {
	return ja4t.fp
}
