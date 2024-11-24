package l4

import (
	"github.com/qencept/gofp/pkg/streamdata"
	"github.com/qencept/gofp/pkg/streamtuple"
	"github.com/qencept/gofp/pkg/tcp/segment"
)

type Stream interface {
	Data() *streamdata.StreamData
	Info() Info
}

type Info interface {
	IsClientToServer() bool
	IsServerToClient() bool
	HandshakeSegment() *segment.Segment
	Tuple() streamtuple.StreamTuple
}

type Dissector interface {
	Dissect(Stream) error
}
