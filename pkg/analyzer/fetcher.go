package analyzer

import (
	"github.com/qencept/gofp/pkg/layers/l1"
)

type Fetcher interface {
	Fetch() (l1.Capture, error)
	Close()
}
