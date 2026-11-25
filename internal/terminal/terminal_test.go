package terminal

import (
	"io"
	"os"
	"strings"
	"testing"
)

// capture redirects the given file (os.Stdout or os.Stderr) to a pipe,
// runs fn, and returns everything written.
func capture(t *testing.T, f **os.File, fn func()) string {
	t.Helper()
	old := *f
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	*f = w
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	fn()

	_ = w.Close()
	*f = old
	return <-done
}

func TestColoredPrintln(t *testing.T) {
	out := capture(t, &os.Stdout, func() {
		ColoredPrintln(Red, "hello", "world")
	})
	want := Red + "hello world\n" + Reset
	if out != want {
		t.Errorf("ColoredPrintln = %q, want %q", out, want)
	}
}

func TestColoredPrintf(t *testing.T) {
	out := capture(t, &os.Stdout, func() {
		ColoredPrintf(Green, "%d items", 3)
	})
	want := Green + "3 items" + Reset
	if out != want {
		t.Errorf("ColoredPrintf = %q, want %q", out, want)
	}
}

func TestColoredError(t *testing.T) {
	out := capture(t, &os.Stderr, func() {
		ColoredError("boom", 42)
	})
	if !strings.Contains(out, "[Error]") {
		t.Errorf("ColoredError missing label: %q", out)
	}
	if !strings.Contains(out, "boom 42") {
		t.Errorf("ColoredError missing values: %q", out)
	}
	if !strings.Contains(out, Red) || !strings.HasSuffix(out, Reset) {
		t.Errorf("ColoredError missing color codes: %q", out)
	}
}

func TestColoredInfo(t *testing.T) {
	out := capture(t, &os.Stderr, func() {
		ColoredInfo("note")
	})
	if !strings.Contains(out, "[Info]") {
		t.Errorf("ColoredInfo missing label: %q", out)
	}
	if !strings.Contains(out, "note") {
		t.Errorf("ColoredInfo missing value: %q", out)
	}
	if !strings.Contains(out, Cyan) || !strings.HasSuffix(out, Reset) {
		t.Errorf("ColoredInfo missing color codes: %q", out)
	}
}