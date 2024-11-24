package pcap

import "time"

type Capture struct {
	timestamp time.Time
	payload   []uint8
}

func (p *Capture) Payload() []uint8 {
	return p.payload
}

func (p *Capture) Timestamp() time.Time {
	return p.timestamp
}
