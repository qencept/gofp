package assembler

import (
	"fmt"
	"time"

	"github.com/qencept/gofp/pkg/layers/l4"
	"github.com/qencept/gofp/pkg/streamtuple"
	"github.com/qencept/gofp/pkg/tcp/segment"
)

type TCPAssembler struct {
	assemblies assemblies
}

type assemblies map[streamtuple.StreamTuple]*streamAssembly

func New() *TCPAssembler {
	return &TCPAssembler{assemblies: make(assemblies)}
}

func (r *TCPAssembler) Assemble(segment *segment.Segment) (l4.Stream, error) {
	assembly, err := manageAssemblies(r.assemblies, segment)
	if err != nil {
		return nil, err
	}

	assembly.trackSegments(segment)

	return assembly.streamUpdate(segment), nil
}

func manageAssemblies(assemblies assemblies, segment *segment.Segment) (*streamAssembly, error) {
	lastSeen := segment.BaseL3().BaseL2().BaseL1().Timestamp()
	cleanExpired(assemblies, lastSeen)

	tuple := assemblyTuple(segment)
	header := segment.Header()
	_, ok := assemblies[tuple]

	if header.SYN && !header.ACK {
		if !ok {
			assemblies[tuple] = newStreamAssembly(clientToServer, tuple)
			ok = true
		} else {
			return nil, fmt.Errorf("client syn expected")
		}
	}

	if header.SYN && header.ACK {
		if !ok {
			assemblies[tuple] = newStreamAssembly(serverToClient, tuple)
			ok = true
		} else {
			return nil, fmt.Errorf("server syn/ack expected")
		}
	}

	if !ok {
		return nil, fmt.Errorf("assembly not found")
	}

	assemblies[tuple].lastSeen = lastSeen

	return assemblies[tuple], nil
}

func assemblyTuple(segment *segment.Segment) streamtuple.StreamTuple {
	ip1 := segment.BaseL3().SrcIP()
	port1 := segment.Header().SrcPort
	ip2 := segment.BaseL3().DstIP()
	port2 := segment.Header().DstPort
	return streamtuple.New(ip1, ip2, port1, port2)
}

const assemblyTimeout = time.Minute

func cleanExpired(assemblies assemblies, timestamp time.Time) {
	for tuple, assembly := range assemblies {
		if timestamp.Sub(assembly.lastSeen) > assemblyTimeout {
			delete(assemblies, tuple)
		}
	}
}
