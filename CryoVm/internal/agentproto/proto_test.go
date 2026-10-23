package agentproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in, err := New(TypeHello, 0, Hello{SandboxID: "demo", Version: "v", PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	ping, _ := New(TypePing, 42, nil)
	for _, m := range []Message{in, ping} {
		if err := Write(&buf, m); err != nil {
			t.Fatal(err)
		}
	}

	got, err := Read(&buf)
	if err != nil || got.Type != TypeHello {
		t.Fatalf("first frame: %+v %v", got, err)
	}
	var h Hello
	if err := got.Decode(&h); err != nil || h.SandboxID != "demo" || h.PID != 1 {
		t.Fatalf("hello body: %+v %v", h, err)
	}
	got, err = Read(&buf)
	if err != nil || got.Type != TypePing || got.ID != 42 {
		t.Fatalf("second frame: %+v %v", got, err)
	}
	if _, err := Read(&buf); err != io.EOF {
		t.Fatalf("clean end: want io.EOF, got %v", err)
	}
}

func TestTruncatedFrame(t *testing.T) {
	var buf bytes.Buffer
	m, _ := New(TypePing, 1, nil)
	_ = Write(&buf, m)
	short := buf.Bytes()[:buf.Len()-3]
	if _, err := Read(bytes.NewReader(short)); err != io.ErrUnexpectedEOF {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestOversizeRejectedBeforeAllocating(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrame+1)
	if _, err := Read(bytes.NewReader(hdr[:])); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
	big, _ := New(TypePing, 1, map[string]string{"x": strings.Repeat("a", MaxFrame)})
	if err := Write(io.Discard, big); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("write: want ErrFrameTooLarge, got %v", err)
	}
}

func TestGarbageAndMissingType(t *testing.T) {
	for _, payload := range []string{"not json", `{"id":1}`} {
		var buf bytes.Buffer
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
		buf.Write(hdr[:])
		buf.WriteString(payload)
		if _, err := Read(&buf); err == nil {
			t.Errorf("accepted %q", payload)
		}
	}
}
