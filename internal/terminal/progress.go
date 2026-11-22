package terminal

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

type UpdateProgress struct {
	mu       sync.Mutex
	bar      *progressbar.ProgressBar
	title    string
	subTitle string
	last     UpdateProgressHandle
}

type UpdateProgressHandle struct {
	Title    string
	SubTitle string
	Current  int
	Total    int
}

func NewUpdateProgress() *UpdateProgress {
	return &UpdateProgress{}
}

func (p *UpdateProgress) Handle(ev UpdateProgressHandle) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.bar == nil || p.title != ev.Title || p.subTitle != ev.SubTitle {
		p.resetBar(ev)
	}
	p.last = ev

	p.bar.Describe(fmt.Sprintf("%s %s", ev.Title, ev.SubTitle))
	_ = p.bar.Add(1)
}

func (p *UpdateProgress) resetBar(ev UpdateProgressHandle) {
	if p.bar != nil {
		_ = p.bar.Finish()
	}
	p.title = ev.Title
	p.subTitle = ev.SubTitle

	opts := []progressbar.Option{
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetWidth(24),
		progressbar.OptionShowCount(),
	}

	// switch ev.Phase {
	// case "importing", "deleting":
	// 	if ev.Total > 0 {
	// 		p.bar = progressbar.NewOptions(ev.Total, append(opts,
	// 			progressbar.OptionSetDescription(ev.Source),
	// 			progressbar.OptionSetTheme(progressbar.ThemeDefault),
	// 			progressbar.OptionShowIts(),
	// 			progressbar.OptionSetItsString("files"),
	// 			progressbar.OptionThrottle(100*time.Millisecond),
	// 			progressbar.OptionOnCompletion(func() { fmt.Fprintln(os.Stderr) }),
	// 		)...)
	// 		return
	// 	}
	// default:
	// }

	p.bar = progressbar.NewOptions(-1, append(opts,
		progressbar.OptionSetDescription(ev.Title),
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
