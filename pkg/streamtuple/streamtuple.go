package streamtuple

import (
	"fmt"
	"net"
	"strings"
)

type StreamTuple string

func New(ip1, ip2 net.IP, port1, port2 uint16) StreamTuple {
	return StreamTuple(fmt.Sprintf("%v:%d->%v:%d", ip1, port1, ip2, port2))
}

func Mirror(tuple StreamTuple) StreamTuple {
	eps := strings.Split(string(tuple), "->")
	return StreamTuple(fmt.Sprintf("%v<-%v", eps[1], eps[0]))
}
