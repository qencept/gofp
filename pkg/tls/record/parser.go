package record

import (
	"github.com/qencept/gofp/pkg/layers/l4"
	"github.com/qencept/gofp/pkg/streamdata"
	"github.com/qencept/gofp/pkg/tls/handshake"
)

type Parser struct {
	handshakeParser *handshake.Parser
}

func NewParser(handshakeParser *handshake.Parser) *Parser {
	return &Parser{handshakeParser: handshakeParser}
}

func (p *Parser) Parse(streamData *streamdata.StreamData, streamInfo l4.Info) error {
	record, ok := &Record{}, false

	if record.Type, ok = streamData.Read1(); !ok {
		return ErrNotEnoughData
	}
	if record.LegacyVersion, ok = streamData.Read2(); !ok {
		return ErrNotEnoughData
	}
	if record.Length, ok = streamData.Read2(); !ok {
		return ErrNotEnoughData
	}

	switch record.Type {
	case RecordHandshake:
		if data, ok := streamData.ReadN(record.Length); ok {
			return p.handshakeParser.Parse(data, streamInfo)
		}
	default:
		if ok := streamData.SkipN(record.Length); ok {
			return nil
		}
	}

	return ErrNotEnoughData
}
