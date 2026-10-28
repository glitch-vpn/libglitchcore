package core

import (
	"os"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

func waitForMirrorIdle() {
	for deadline := time.Now().Add(5 * time.Second); !stdoutMirror.idle() && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEmitLog_UnreadStdoutDoesNotBlockAndStatusPortGetsEveryLine(t *testing.T) {
	const lines = 4096
	logs := captureLogs(t, 2)

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	waitForMirrorIdle()
	realStdout := os.Stdout
	os.Stdout = writer
	t.Cleanup(func() {
		// Closing the reader fails the writes the mirror still has queued, and
		// os.Stdout goes back only once it has none: it reads the variable.
		reader.Close()
		waitForMirrorIdle()
		os.Stdout = realStdout
		writer.Close()
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range lines {
			emitLog(logfmt.Info, "test", "a line long enough to fill a pipe buffer quickly: 0123456789abcdef0123456789abcdef")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("emitLog blocked on a stdout nobody reads")
	}

	deadline := time.Now().Add(5 * time.Second)
	for len(logs()) < lines {
		if time.Now().After(deadline) {
			t.Fatalf("status port got %d of %d lines", len(logs()), lines)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
