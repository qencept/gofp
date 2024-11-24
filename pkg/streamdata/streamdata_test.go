package streamdata

import "testing"

func TestStream(t *testing.T) {
	stream := New()
	stream.Push([]byte("abc"))
	stream.Push([]byte("defg"))
	stream.Push([]byte("hi"))
	stream.Push([]byte("jklmnop"))

	if b, ok := stream.ReadN(4); !ok || string(b) != "abcd" {
		t.Fatal(string(b))
	}
	if b, ok := stream.ReadN(1); !ok || string(b) != "e" {
		t.Fatal(string(b))
	}
	if b, ok := stream.ReadN(7); !ok || string(b) != "fghijkl" {
		t.Fatal(string(b))
	}
	if b, ok := stream.ReadN(4); !ok || string(b) != "mnop" {
		t.Fatal(string(b))
	}
	if b, ok := stream.ReadN(1); ok {
		t.Fatal(string(b))
	}

	stream.Revert(0)
	if b, ok := stream.ReadN(4); !ok || string(b) != "abcd" {
		t.Fatal(string(b))
	}

	offset := stream.Offset()
	if b, ok := stream.ReadN(6); !ok || string(b) != "efghij" {
		t.Fatal(string(b))
	}
	stream.Revert(offset)
	if b, ok := stream.ReadN(6); !ok || string(b) != "efghij" {
		t.Fatal(string(b))
	}
	stream.Revert(offset)
	if b, ok := stream.ReadN(7); !ok || string(b) != "efghijk" {
		t.Fatal(string(b))
	}

	stream.Commit(offset)
	if len(stream.chunks) != 3 {
		t.Fatal(len(stream.chunks))
	}
	stream.Commit(stream.Offset())
	if len(stream.chunks) != 1 {
		t.Fatal(len(stream.chunks))
	}
	if b, ok := stream.ReadN(4); !ok || string(b) != "lmno" {
		t.Fatal(string(b))
	}
}
