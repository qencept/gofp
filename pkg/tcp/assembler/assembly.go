package assembler

import (
	"sort"
	"time"

	"github.com/qencept/gofp/pkg/layers/l4"
	"github.com/qencept/gofp/pkg/streamdata"
	"github.com/qencept/gofp/pkg/streamtuple"
	"github.com/qencept/gofp/pkg/tcp/segment"
)

type streamAssembly struct {
	handshakeSegment *segment.Segment
	clientToServer   bool
	segmentsTotal    int
	lastSeen         time.Time
	stream           *streamdata.StreamData
	tuple            streamtuple.StreamTuple
	ooo              []*segment.Segment
	seq              int
}

const (
	clientToServer = true
	serverToClient = false
)

func newStreamAssembly(clientToServer bool, tuple streamtuple.StreamTuple) *streamAssembly {
	return &streamAssembly{clientToServer: clientToServer, tuple: tuple, stream: streamdata.New()}
}

func (a *streamAssembly) trackSegments(segment *segment.Segment) {
	a.segmentsTotal++
	if a.segmentsTotal == 1 {
		a.seq = segment.Header().SeqNumber + 1
		a.handshakeSegment = segment
	}
}

func (a *streamAssembly) streamUpdate(segment *segment.Segment) *streamUpdate {
	update := &streamUpdate{streamAssembly: a}

	if len(segment.Payload()) > 0 {
		if update.appendStream(segment) {
			for len(a.ooo) > 0 && update.appendStream(a.ooo[0]) {
				a.ooo = a.ooo[1:]
			}
		} else {
			a.appendOOO(segment)
		}
	}

	return update
}

func (a *streamAssembly) appendOOO(segment *segment.Segment) {
	if a.seq < segment.Header().SeqNumber+len(segment.Payload()) {
		a.ooo = append(a.ooo, segment)
		sort.Slice(a.ooo, func(i, j int) bool { //!!! optimize ooo storage (?heap)
			return a.ooo[i].Header().SeqNumber < a.ooo[j].Header().SeqNumber
		})
	}
}

type streamUpdate struct {
	streamAssembly *streamAssembly
}

func (u *streamUpdate) appendStream(segment *segment.Segment) bool {
	assembly := u.streamAssembly
	if segment.Header().SeqNumber <= assembly.seq {
		if assembly.seq < segment.Header().SeqNumber+len(segment.Payload()) {
			begin := assembly.seq - segment.Header().SeqNumber
			end := segment.Header().SeqNumber + len(segment.Payload()) - assembly.seq
			chunk := segment.Payload()[begin:end]
			u.streamAssembly.stream.Push(chunk)
			assembly.seq += end - begin
		}
		return true
	}
	return false
}

func (a *streamAssembly) IsClientToServer() bool {
	return a.clientToServer
}

func (a *streamAssembly) IsServerToClient() bool {
	return !a.IsClientToServer()
}

func (a *streamAssembly) HandshakeSegment() *segment.Segment {
	return a.handshakeSegment
}

func (a *streamAssembly) Tuple() streamtuple.StreamTuple {
	return a.tuple
}

func (u *streamUpdate) Data() *streamdata.StreamData {
	return u.streamAssembly.stream
}

func (u *streamUpdate) Info() l4.Info {
	return u.streamAssembly
}
