package dissector

import (
	"errors"

	"github.com/qencept/gofp/pkg/layers/l4"
	"github.com/qencept/gofp/pkg/tls/handshake"
	"github.com/qencept/gofp/pkg/tls/record"
)

type Dissector struct {
	recordParser *record.Parser
}

func New(clientHelloHandler handshake.ClientHelloHandler, serverHelloHandler handshake.ServerHelloHandler) *Dissector {
	handshakeParser := handshake.NewParser(clientHelloHandler, serverHelloHandler)
	recordParser := record.NewParser(handshakeParser)
	return &Dissector{recordParser: recordParser}
}

func (p *Dissector) Dissect(stream l4.Stream) error {
	streamData := stream.Data()

	for streamData.HasMore() {
		offset := streamData.Offset()
		err := p.recordParser.Parse(streamData, stream.Info())
		if errors.Is(err, record.ErrNotEnoughData) {
			streamData.Revert(offset)
			return nil
		}
		if err != nil {
			return err
		}
		streamData.Commit(offset)
	}

	return nil
}
