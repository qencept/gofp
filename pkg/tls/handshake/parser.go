package handshake

import (
	"encoding/binary"

	"github.com/qencept/gofp/pkg/layers/l4"
	"github.com/qencept/gofp/pkg/tls/clienthello"
	"github.com/qencept/gofp/pkg/tls/serverhello"
)

type Parser struct {
	clientHelloHandler ClientHelloHandler
	serverHelloHandler ServerHelloHandler
}

type ClientHelloHandler func(clientHello *clienthello.ClientHello, streamInfo l4.Info)
type ServerHelloHandler func(serverHello *serverhello.ServerHello, streamInfo l4.Info)

func NewParser(clientHelloHandler ClientHelloHandler, serverHelloHandler ServerHelloHandler) *Parser {
	return &Parser{
		clientHelloHandler: clientHelloHandler,
		serverHelloHandler: serverHelloHandler,
	}
}

func (p *Parser) Parse(data []uint8, streamInfo l4.Info) error {
	if len(data) < 4 {
		return ErrUnexpectedHandshake
	}

	handshake := &HandshakeHeader{
		MessageType: int(data[0]),
		Length:      int(binary.BigEndian.Uint32(data[0:4]) & 0xFFFFFF),
	}
	data = data[4:]

	if len(data) < handshake.Length {
		return ErrUnexpectedHandshake
	}
	data = data[:handshake.Length]

	switch handshake.MessageType {
	case MessageClientHello:
		clientHello, err := clienthello.ParseClientHello(data)
		if err != nil {
			return err
		}
		p.clientHelloHandler(clientHello, streamInfo)
	case MessageServerHello:
		serverHello, err := serverhello.ParseServerHello(data)
		if err != nil {
			return err
		}
		p.serverHelloHandler(serverHello, streamInfo)
	}

	return nil
}
