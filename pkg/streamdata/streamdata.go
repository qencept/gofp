package streamdata

import (
	"encoding/binary"
)

type StreamData struct {
	chunks [][]uint8
	total  int
	offset int
}

func New() *StreamData {
	return &StreamData{}
}

func (s *StreamData) Push(chunk []byte) {
	s.chunks = append(s.chunks, chunk)
	s.total += len(chunk)
}

func (s *StreamData) SkipN(n int) bool {
	if n > s.total-s.offset {
		return false
	}
	s.offset += n
	return true
}

func (s *StreamData) ReadN(n int) ([]uint8, bool) {
	p := make([]uint8, n)
	if n > s.total-s.offset {
		return nil, false
	}
	idx, offset := 0, s.offset
	for idx = 0; len(s.chunks[idx]) < offset; idx++ {
		offset -= len(s.chunks[idx])
	}
	pos := 0
	need := n
	for need > 0 {
		avail := len(s.chunks[idx]) - offset
		count := min(avail, need)
		copy(p[pos:pos+count], s.chunks[idx][offset:])
		need -= count
		pos += count
		offset += count
		if offset == len(s.chunks[idx]) {
			offset = 0
			idx++
		}
	}
	s.offset += n
	return p, true
}

func (s *StreamData) Read1() (int, bool) {
	if p, ok := s.ReadN(1); ok {
		return int(p[0]), true
	}
	return 0, false
}

func (s *StreamData) Read2() (int, bool) {
	if p, ok := s.ReadN(2); ok {
		return int(binary.BigEndian.Uint16(p)), true
	}
	return 0, false
}

func (s *StreamData) Offset() int {
	return s.offset
}

func (s *StreamData) Revert(offset int) {
	s.offset = offset
}

func (s *StreamData) Commit(offset int) {
	for len(s.chunks[0]) <= offset {
		offset -= len(s.chunks[0])
		s.offset -= len(s.chunks[0])
		s.total -= len(s.chunks[0])
		s.chunks = s.chunks[1:]
	}
}

func (s *StreamData) HasMore() bool {
	return s.offset < s.total-1
}
