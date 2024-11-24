package serverhello

import (
	"encoding/binary"
	"errors"

	"github.com/qencept/gofp/pkg/tls/clienthello"
)

type ServerHello struct {
	Version                   uint16
	Random                    []uint8
	SessionIDLength           uint8
	SessionID                 []uint8
	CipherSuite               uint16
	CompressionMethod         uint8
	ExtensionsLength          uint16
	ExtensionTypes            []uint16
	ExtensionALPN             string
	ExtensionSupportedVersion uint16
}

var ErrUnexpectedServerHello = errors.New("tls unexpected server hello")

func ParseServerHello(data []uint8) (*ServerHello, error) {
	if len(data) < 35 {
		return nil, ErrUnexpectedServerHello
	}
	serverHello := &ServerHello{
		Version:         binary.BigEndian.Uint16(data[:2]),
		Random:          data[2:34],
		SessionIDLength: data[34],
	}
	data = data[35:]

	if len(data) < int(serverHello.SessionIDLength) {
		return nil, ErrUnexpectedServerHello
	}
	serverHello.SessionID = data[:serverHello.SessionIDLength]
	data = data[serverHello.SessionIDLength:]

	if len(data) < 2 {
		return nil, ErrUnexpectedServerHello
	}
	serverHello.CipherSuite = binary.BigEndian.Uint16(data[:2])
	data = data[2:]

	if len(data) < 1 {
		return nil, ErrUnexpectedServerHello
	}
	serverHello.CompressionMethod = data[0]
	data = data[1:]

	if len(data) < 2 {
		return nil, ErrUnexpectedServerHello
	}
	serverHello.ExtensionsLength = binary.BigEndian.Uint16(data[:2])
	data = data[2:]

	if len(data) < int(serverHello.ExtensionsLength) {
		return nil, ErrUnexpectedServerHello
	}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, ErrUnexpectedServerHello
		}
		extension := &clienthello.Extension{
			Type:   binary.BigEndian.Uint16(data[:2]),
			Length: int(binary.BigEndian.Uint16(data[2:4])),
		}
		data = data[4:]

		if len(data) < extension.Length {
			return nil, ErrUnexpectedServerHello
		}
		extension.Data = data[:extension.Length]
		data = data[extension.Length:]

		if !isGREASE(extension.Type) {
			serverHello.ExtensionTypes = append(serverHello.ExtensionTypes, extension.Type)
			switch extension.Type {
			case clienthello.ExtensionALPN:
				if len(extension.Data) < 2 {
					return nil, ErrUnexpectedServerHello
				}
				d := extension.Data[2:]
				if len(d) < 1 {
					return nil, ErrUnexpectedServerHello
				}
				l := d[0]
				d = d[1:]
				if len(d) < int(l) {
					return nil, ErrUnexpectedServerHello
				}
				serverHello.ExtensionALPN = string(d[:l])
			case clienthello.ExtensionSupportedVersions:
				if len(extension.Data) < 2 {
					return nil, ErrUnexpectedServerHello
				}
				d := extension.Data[:2]
				v := binary.BigEndian.Uint16(d[:2])
				if !isGREASE(v) {
					serverHello.ExtensionSupportedVersion = v
				}
			}
		}
	}

	return serverHello, nil
}

func isGREASE(val uint16) bool {
	return val>>8 == val&0xff && val&0x0f == 0xa
}
