package terminal

import (
	"core/internal/vulnerability"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

type UpdateProgress struct {
	mu     sync.Mutex
	bar    *progressbar.ProgressBar
	phase  string
	source string
	last   vulnerability.UpdateProgress
}

func NewUpdateProgress() *UpdateProgress {
	return &UpdateProgress{}
}

func (p *UpdateProgress) Handle(ev vulnerability.UpdateProgress) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.bar == nil || p.phase != ev.Phase || p.source != ev.Source || (ev.Phase == "importing" && p.bar.GetMax() != ev.Total) {
		p.resetBar(ev)
	}
	p.last = ev

	switch ev.Phase {
	case "importing":
		desc := fmt.Sprintf("%s imported:%d skipped:%d", ev.Source, ev.Imported, ev.Skipped)
		p.bar.Describe(desc)
		if ev.Total > 0 {
			_ = p.bar.Set(ev.Current)
		} else {
			_ = p.bar.Add(1)
		}
	case "deleting":
		desc := fmt.Sprintf("%s deleted:%d", ev.Source, ev.Deleted)
		p.bar.Describe(desc)
		if ev.Total > 0 {
			_ = p.bar.Set(ev.Current)
		} else {
			_ = p.bar.Add(1)
		}
	case "diffing":
		p.bar.Describe(fmt.Sprintf("%s diffing", ev.Source))
		_ = p.bar.Add(1)
	case "syncing":
		p.bar.Describe(fmt.Sprintf("%s syncing", ev.Source))
		_ = p.bar.Add(1)
	default:
		p.bar.Describe(fmt.Sprintf("%s %s", ev.Source, ev.Phase))
		_ = p.bar.Add(1)
	}
}

func (p *UpdateProgress) resetBar(ev vulnerability.UpdateProgress) {
	if p.bar != nil {
		_ = p.bar.Finish()
	}
	p.phase = ev.Phase
	p.source = ev.Source

	opts := []progressbar.Option{
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetWidth(24),
		progressbar.OptionShowCount(),
	}

	switch ev.Phase {
	case "importing", "deleting":
		if ev.Total > 0 {
			p.bar = progressbar.NewOptions(ev.Total, append(opts,
				progressbar.OptionSetDescription(ev.Source),
				progressbar.OptionSetTheme(progressbar.ThemeDefault),
				progressbar.OptionShowIts(),
				progressbar.OptionSetItsString("files"),
				progressbar.OptionThrottle(100*time.Millisecond),
				progressbar.OptionOnCompletion(func() { fmt.Fprintln(os.Stderr) }),
			)...)
			return
		}
	default:
	}

	p.bar = progressbar.NewOptions(-1, append(opts,
		progressbar.OptionSetDescription(ev.Source),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionThrottle(100*time.Millisecond),
	)...)
}

func (p *UpdateProgress) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bar != nil {
		if !p.bar.IsFinished() {
			_ = p.bar.Finish()
			fmt.Fprintln(os.Stderr)
		}
		p.bar = nil
	}
}
