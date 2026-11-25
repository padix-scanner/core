package terminal

import (
	"os"
	"testing"
)

func TestNewUpdateProgress(t *testing.T) {
	p := NewUpdateProgress()
	if p == nil {
		t.Fatal("NewUpdateProgress returned nil")
	}
	if p.bar != nil {
		t.Error("new progress should have nil bar")
	}
}

func TestUpdateProgressHandleUpdatesLast(t *testing.T) {
	p := NewUpdateProgress()
	// Redirect stderr so progress rendering does not pollute test output.
	out := capture(t, &os.Stderr, func() {
		p.Handle(UpdateProgressHandle{Title: "Scan", SubTitle: "host1", Current: 1, Total: 3})
	})
	_ = out

	if p.last.Title != "Scan" || p.last.SubTitle != "host1" {
		t.Errorf("last = %+v, want Title=Scan SubTitle=host1", p.last)
	}
}

func TestUpdateProgressHandleResetsOnTitleChange(t *testing.T) {
	p := NewUpdateProgress()
	_ = capture(t, &os.Stderr, func() {
		p.Handle(UpdateProgressHandle{Title: "A", SubTitle: "x"})
		first := p.bar
		p.Handle(UpdateProgressHandle{Title: "B", SubTitle: "x"})
		if p.bar == first {
			t.Error("bar should be recreated when title changes")
		}
	})
}

func TestUpdateProgressFinishIdempotent(t *testing.T) {
	p := NewUpdateProgress()
	_ = capture(t, &os.Stderr, func() {
		p.Handle(UpdateProgressHandle{Title: "A"})
		p.Finish()
		if p.bar != nil {
			t.Error("bar should be nil after Finish")
		}
		// Second Finish must not panic.
		p.Finish()
	})
}

func TestUpdateProgressFinishWithoutBar(t *testing.T) {
	p := NewUpdateProgress()
	// Finish with no bar should be a no-op, not a panic.
	p.Finish()
	if p.bar != nil {
		t.Error("bar should remain nil")
	}
}