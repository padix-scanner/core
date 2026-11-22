package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"core/internal/vulnerability"
	"core/pkg/constants"

	"github.com/schollz/progressbar/v3"
)

func runDB(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(
			"missing database subcommand; usage: %s db <update|status> [options]",
			appCommandName,
		)
	}

	switch args[0] {
	case "update":
		return runDBUpdate(args[1:])
	case "status":
		return runDBStatus(args[1:])
	default:
		return fmt.Errorf(
			"unknown database command %q; available commands: update, status",
			args[0],
		)
	}
}

type updateProgress struct {
	mu     sync.Mutex
	bar    *progressbar.ProgressBar
	phase  string
	source string
	last   vulnerability.UpdateProgress
}

func newUpdateProgress() *updateProgress {
	return &updateProgress{}
}

func (p *updateProgress) Handle(ev vulnerability.UpdateProgress) {
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

func (p *updateProgress) resetBar(ev vulnerability.UpdateProgress) {
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

func (p *updateProgress) Finish() {
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

func runDBStatus(args []string) error {
	flags := flag.NewFlagSet("db status", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	dbPath := flags.String(
		"db",
		constants.DefaultCVEDatabasePath,
		"SQLite database path",
	)

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	fmt.Println("Padix CVE Database Status")
	fmt.Printf("Database: %s\n", *dbPath)

	info, err := os.Stat(*dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Status:   missing")
			fmt.Println("Run `padix db update` to create and populate the database.")
			return nil
		}
		return fmt.Errorf("stat database: %w", err)
	}

	db, err := vulnerability.OpenDB(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	status, err := db.Status(ctx)
	if err != nil {
		return err
	}
	status.Path = *dbPath
	status.Exists = true
	status.SizeBytes = info.Size()

	fmt.Println("Status:   ready")
	fmt.Printf("Size:     %s\n", formatBytes(status.SizeBytes))
	fmt.Printf("CVEs:     %d\n", status.CVEs)
	fmt.Printf("Products: %d\n", status.Products)
	fmt.Printf("Refs:     %d\n", status.References)
	fmt.Printf("Weakness: %d\n", status.Weaknesses)

	if len(status.SyncStates) == 0 {
		fmt.Println("Sync:     no sync state")
		return nil
	}

	fmt.Println("Sync:")
	for _, s := range status.SyncStates {
		lastSync := "never"
		if s.LastSyncAt != nil {
			lastSync = s.LastSyncAt.UTC().Format(time.RFC3339)
		}
		fmt.Printf(
			"  - %s: status=%s last_sync=%s commit=%s records=%d\n",
			s.Source,
			defaultDBStatusValue(s.Status, "never"),
			lastSync,
			defaultDBStatusValue(s.LastCommit, "-"),
			s.RecordsProcessed,
		)
		if strings.TrimSpace(s.LastError) != "" {
			fmt.Printf("    last_error=%s\n", s.LastError)
		}
	}

	return nil
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func defaultDBStatusValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func runDBUpdate(args []string) error {
	flags := flag.NewFlagSet("db update", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	dbPath := flags.String(
		"db",
		constants.DefaultCVEDatabasePath,
		"SQLite database path",
	)
	sourcesPath := flags.String(
		"sources",
		constants.DefaultCVESourceConfig,
		"vulnerability source configuration",
	)
	cacheDir := flags.String(
		"cache",
		constants.DefaultCVECacheDir,
		"local source cache directory",
	)
	incremental := flags.Bool(
		"incremental",
		true,
		"import only files changed since the last successful update",
	)
	full := flags.Bool(
		"full",
		false,
		"re-import all CVE files",
	)

	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	if *full {
		*incremental = false
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	fmt.Printf("%s CVE Database Update\n", constants.AppName)
	fmt.Printf("Database: %s\n", *dbPath)

	sources, err := vulnerability.LoadSources(*sourcesPath)
	if err != nil {
		return err
	}

	db, err := vulnerability.OpenDB(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	updater := vulnerability.NewUpdater(
		db.GORM(),
		vulnerability.UpdaterConfig{
			CacheDir: *cacheDir,
		},
	)

	progress := newUpdateProgress()
	summary, err := updater.Update(
		ctx,
		sources,
		vulnerability.UpdateOptions{
			Incremental: *incremental,
			OnProgress:  progress.Handle,
		},
	)
	progress.Finish()
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("CVE database update completed.")
	fmt.Printf("Sources processed: %d\n", summary.Sources)
	fmt.Printf("Files processed:   %d\n", summary.Files)
	fmt.Printf("CVEs imported:     %d\n", summary.Imported)
	fmt.Printf("CVEs deleted:      %d\n", summary.Deleted)
	fmt.Printf("Skipped:           %d\n", summary.Skipped)

	return nil
}
