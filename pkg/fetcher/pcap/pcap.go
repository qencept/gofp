package pcap

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/qencept/gofp/pkg/analyzer"
	"github.com/qencept/gofp/pkg/layers/l1"
)

type Pcap struct {
	handle       *pcap.Handle
	packetSource *gopacket.PacketSource
}

func NewLive(device, filter string) (analyzer.Fetcher, error) {
	handle, err := pcap.OpenLive(device, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("could not open device: %w", err)
	}

	if err = handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("could not set BPFFilter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	return &Pcap{packetSource: packetSource}, nil
}

func NewOffline(filename, filter string) (analyzer.Fetcher, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %w", err)
	}

	if filter != "" {
		if err = handle.SetBPFFilter(filter); err != nil {
			return nil, fmt.Errorf("could not set BPFFilter: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	return &Pcap{handle: handle, packetSource: packetSource}, nil
}

func (p *Pcap) Fetch() (l1.Capture, error) {
	pkt, err := p.packetSource.NextPacket()
	if err != nil {
		return nil, err
	}
	return &Capture{
		timestamp: pkt.Metadata().Timestamp,
		payload:   pkt.Data(),
	}, nil
}

func (p *Pcap) Close() {
	p.handle.Close()
}
