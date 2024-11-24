package main

import (
	"fmt"
	"log"

	"github.com/qencept/gofp/pkg/analyzer"
	"github.com/qencept/gofp/pkg/fetcher/pcap"
	"github.com/qencept/gofp/pkg/fp/ja4"
	"github.com/qencept/gofp/pkg/fp/ja4s"
	"github.com/qencept/gofp/pkg/fp/ja4t"
	"github.com/qencept/gofp/pkg/layers/l4"
	"github.com/qencept/gofp/pkg/tls/clienthello"
	"github.com/qencept/gofp/pkg/tls/serverhello"
)

func main() {
	//source, err := pcap.NewLive("en0", "tcp")
	source, err := pcap.NewOffline("./samples/tls_marmot_safari.pcap", "")
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()

	instance := analyzer.New(
		analyzer.WithSource(source),
		analyzer.WithClientHelloHandler(clientHelloHandler),
		analyzer.WithServerHelloHandler(serverHelloHandler),
	)
	err = instance.Handle()
	if err != nil {
		log.Fatal(err)
	}
}

func clientHelloHandler(clientHello *clienthello.ClientHello, streamInfo l4.Info) {
	tuple := streamInfo.Tuple()
	TTL := streamInfo.HandshakeSegment().BaseL3().TTL()
	JA4T := ja4t.New(streamInfo.HandshakeSegment().Header())
	JA4 := ja4.New(clientHello)
	fmt.Printf("%v %v %-30v %v\n", tuple, TTL, JA4T, JA4)
}

func serverHelloHandler(serverHello *serverhello.ServerHello, streamInfo l4.Info) {
	tuple := streamInfo.Tuple()
	TTL := streamInfo.HandshakeSegment().BaseL3().TTL()
	JA4T := ja4t.New(streamInfo.HandshakeSegment().Header())
	JA4S := ja4s.New(serverHello)
	fmt.Printf("%v %v %-30v %v\n", tuple, TTL, JA4T, JA4S)
}
