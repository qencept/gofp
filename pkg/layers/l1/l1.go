package l1

import "time"

type Capture interface {
	Timestamp() time.Time
	Payload() []uint8
}

type Dissector interface {
	Dissect(Capture) error
}
