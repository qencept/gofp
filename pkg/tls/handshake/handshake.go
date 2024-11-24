package handshake

import (
	"errors"
)

type HandshakeHeader struct {
	MessageType int
	Length      int
}

const (
	MessageClientHello = 1
	MessageServerHello = 2
)

var ErrUnexpectedHandshake = errors.New("tls unexpected handshake")
