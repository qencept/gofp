package clienthello

import (
	"encoding/binary"
	"errors"
)

type ClientHello struct {
	Version                    uint16
	Random                     []uint8
	SessionIDLength            uint8
	SessionID                  []uint8
	CipherSuitesLength         uint16
	CipherSuites               []uint16
	CompressionMethodsLength   uint8
	CompressionMethods         []uint8
	ExtensionsLength           uint16
	ExtensionTypes             []uint16
	ExtensionSNI               string
	ExtensionALPN              []string
	ExtensionSignatures        []uint16
	ExtensionSupportedVersions []uint16
}

var ErrUnexpectedClientHello = errors.New("tls unexpected client hello")

func ParseClientHello(data []uint8) (*ClientHello, error) {
	if len(data) < 35 {
		return nil, ErrUnexpectedClientHello
	}
	clientHello := &ClientHello{
		Version:         binary.BigEndian.Uint16(data[:2]),
		Random:          data[2:34],
		SessionIDLength: data[34],
	}
	data = data[35:]

	if len(data) < int(clientHello.SessionIDLength) {
		return nil, ErrUnexpectedClientHello
	}
	clientHello.SessionID = data[:clientHello.SessionIDLength]
	data = data[clientHello.SessionIDLength:]

	if len(data) < 2 {
		return nil, ErrUnexpectedClientHello
	}
	clientHello.CipherSuitesLength = binary.BigEndian.Uint16(data[:2])
	data = data[2:]

	if len(data) < int(clientHello.CipherSuitesLength) {
		return nil, ErrUnexpectedClientHello
	}
	for cipherSuite := data[:clientHello.CipherSuitesLength]; len(cipherSuite) > 0; cipherSuite = cipherSuite[2:] {
		cs := binary.BigEndian.Uint16(cipherSuite[:2])
		if !isGREASE(cs) {
			clientHello.CipherSuites = append(clientHello.CipherSuites, cs)
		}
	}
	data = data[clientHello.CipherSuitesLength:]

	if len(data) < 1 {
		return nil, ErrUnexpectedClientHello
	}
	clientHello.CompressionMethodsLength = data[0]
	data = data[1:]

	if len(data) < int(clientHello.CompressionMethodsLength) {
		return nil, ErrUnexpectedClientHello
	}
	clientHello.CompressionMethods = data[:clientHello.CompressionMethodsLength]
	data = data[clientHello.CompressionMethodsLength:]

	if len(data) < 2 {
		return nil, ErrUnexpectedClientHello
	}
	clientHello.ExtensionsLength = binary.BigEndian.Uint16(data[:2])
	data = data[2:]

	if len(data) < int(clientHello.ExtensionsLength) {
		return nil, ErrUnexpectedClientHello
	}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, ErrUnexpectedClientHello
		}
		extension := &Extension{
			Type:   binary.BigEndian.Uint16(data[:2]),
			Length: int(binary.BigEndian.Uint16(data[2:4])),
		}
		data = data[4:]

		if len(data) < extension.Length {
			return nil, ErrUnexpectedClientHello
		}
		extension.Data = data[:extension.Length]
		data = data[extension.Length:]

		if !isGREASE(extension.Type) {
			clientHello.ExtensionTypes = append(clientHello.ExtensionTypes, extension.Type)
			switch extension.Type {
			case ExtensionSNI:
				if len(extension.Data) < 5 {
					return nil, ErrUnexpectedClientHello
				}
				d := extension.Data[3:]
				if len(d) < 2 {
					return nil, ErrUnexpectedClientHello
				}
				l := int(binary.BigEndian.Uint16(d[:2]))
				d = d[2:]
				if len(d) < l {
					return nil, ErrUnexpectedClientHello
				}
				clientHello.ExtensionSNI = string(d[:l])
			case ExtensionALPN:
				if len(extension.Data) < 2 {
					return nil, ErrUnexpectedClientHello
				}
				d := extension.Data[2:]
				for len(d) > 0 {
					if len(d) < 1 {
						return nil, ErrUnexpectedClientHello
					}
					l := d[0]
					d = d[1:]
					if len(d) < int(l) {
						return nil, ErrUnexpectedClientHello
					}
					clientHello.ExtensionALPN = append(clientHello.ExtensionALPN, string(d[:l]))
					d = d[l:]
				}
			case ExtensionAlgorithms:
				if len(extension.Data) < 2 {
					return nil, ErrUnexpectedClientHello
				}
				d := extension.Data[2:]
				for len(d) > 0 {
					if len(d) < 2 {
						return nil, ErrUnexpectedClientHello
					}
					clientHello.ExtensionSignatures = append(clientHello.ExtensionSignatures, binary.BigEndian.Uint16(d[:2]))
					d = d[2:]
				}
			case ExtensionSupportedVersions:
				if len(extension.Data) < 1 {
					return nil, ErrUnexpectedClientHello
				}
				d := extension.Data[1:]
				for len(d) > 0 {
					if len(d) < 2 {
						return nil, ErrUnexpectedClientHello
					}
					v := binary.BigEndian.Uint16(d[:2])
					if !isGREASE(v) {
						clientHello.ExtensionSupportedVersions = append(clientHello.ExtensionSupportedVersions, v)
					}
					d = d[2:]
				}
			}
		}
	}

	return clientHello, nil
}

type Extension struct {
	Type   uint16
	Length int
	Data   []uint8
}

const (
	ExtensionSNI               = 0
	ExtensionALPN              = 16
	ExtensionAlgorithms        = 13
	ExtensionSupportedVersions = 43
)

func isGREASE(val uint16) bool {
	return val>>8 == val&0xff && val&0x0f == 0xa
}
