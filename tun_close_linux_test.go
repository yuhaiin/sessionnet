//go:build linux

package sessionnet

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestDuplicatedPacketFDCloseInterruptsRead(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	session := &Session{tun: read, name: "packet-test"}
	fd, err := session.DupTun()
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() { close(started); var buffer [1]byte; _, err := fd.Read(buffer[:]); done <- err }()
	<-started
	// Keep the writer open: EOF must not be what releases the reader.
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("interrupted read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet FD close did not interrupt read")
	}
}
