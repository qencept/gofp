package analyzer

import (
	"fmt"
	"io"

	arpdissector "github.com/qencept/gofp/pkg/arp/dissector"
	ethdissector "github.com/qencept/gofp/pkg/eth/dissector"
	ethframe "github.com/qencept/gofp/pkg/eth/frame"
	icmp4dissector "github.com/qencept/gofp/pkg/icmp4/dissector"
	ip4disector "github.com/qencept/gofp/pkg/ip4/dissector"
	ip4packet "github.com/qencept/gofp/pkg/ip4/packet"
	ip6disector "github.com/qencept/gofp/pkg/ip6/dissector"
	ip6packet "github.com/qencept/gofp/pkg/ip6/packet"
	"github.com/qencept/gofp/pkg/layers/l1"
	tcpassembler "github.com/qencept/gofp/pkg/tcp/assembler"
	tcpdissector "github.com/qencept/gofp/pkg/tcp/dissector"
	tlsdissector "github.com/qencept/gofp/pkg/tls/dissector"
	"github.com/qencept/gofp/pkg/tls/handshake"
)

type Analyzer struct {
	source             Fetcher
	next               l1.Dissector
	clientHelloHandler handshake.ClientHelloHandler
	serverHelloHandler handshake.ServerHelloHandler
}

func New(options ...func(*Analyzer)) *Analyzer {
	analyzer := &Analyzer{}
	for _, opt := range options {
		opt(analyzer)
	}

	tlsDissector := tlsdissector.New(analyzer.clientHelloHandler, analyzer.serverHelloHandler)

	tcpDissector := tcpdissector.New(tcpassembler.New(), tlsDissector)

	ip6Dissector := ip6disector.New(ip6disector.NextDissectors{
		ip6packet.NextHeaderTCP: tcpDissector,
	})

	ip4Dissector := ip4disector.New(ip4disector.NextDissectors{
		ip4packet.IPProtoICMP4: icmp4dissector.New(),
		ip4packet.IPProtoTCP:   tcpDissector,
	})

	ethDissector := ethdissector.New(ethdissector.NextDissector{
		ethframe.EtherTypeARP:  arpdissector.New(),
		ethframe.EtherTypeIPv4: ip4Dissector,
		ethframe.EtherTypeIPv6: ip6Dissector,
	})

	analyzer.next = ethDissector

	return analyzer
}

func WithSource(source Fetcher) func(analyzer *Analyzer) {
	return func(s *Analyzer) {
		s.source = source
	}
}

func WithClientHelloHandler(clientHelloHandler handshake.ClientHelloHandler) func(analyzer *Analyzer) {
	return func(s *Analyzer) {
		s.clientHelloHandler = clientHelloHandler
	}
}

func WithServerHelloHandler(serverHelloHandler handshake.ServerHelloHandler) func(analyzer *Analyzer) {
	return func(s *Analyzer) {
		s.serverHelloHandler = serverHelloHandler
	}
}

func (p *Analyzer) Handle() error {
	for {
		capture, err := p.source.Fetch()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		err = p.next.Dissect(capture)
		if err != nil {
			fmt.Printf("... %v\n", err)
		}
	}
}
