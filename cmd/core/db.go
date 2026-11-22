package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"core/internal/vulnerability"
	"core/pkg/constants"
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
	w         io.Writer
	mu        sync.Mutex
	lastDraw  time.Time
	lastWidth int
	active    bool
}

func newUpdateProgress(w io.Writer) *updateProgress {
	return &updateProgress{w: w}
}

func (p *updateProgress) Handle(ev vulnerability.UpdateProgress) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if time.Since(p.lastDraw) < 100*time.Millisecond &&
		ev.Phase == "importing" && ev.Current < ev.Total {
		return
	}

	line := renderUpdateProgress(ev)
	width := len([]rune(line))
	padding := ""
	if p.lastWidth > width {
		padding = strings.Repeat(" ", p.lastWidth-width)
	}

	fmt.Fprintf(p.w, "\r%s%s", line, padding)
	p.lastWidth = width
	p.lastDraw = time.Now()
	p.active = true
}

func (p *updateProgress) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active {
		fmt.Fprintln(p.w)
		p.active = false
	}
}

func renderUpdateProgress(ev vulnerability.UpdateProgress) string {
	label := ev.Source
	if label == "" {
		label = "source"
	}

	switch ev.Phase {
	case "syncing":
		return fmt.Sprintf("[%-10s] %s", "sync", label)
	case "diffing":
		return fmt.Sprintf("[%-10s] %s", "diff", label)
	case "deleting":
		if ev.Total > 0 {
			return fmt.Sprintf("[%-10s] %s %d/%d deleted:%d", "delete", label, ev.Current, ev.Total, ev.Deleted)
		}
		return fmt.Sprintf("[%-10s] %s deleted:%d", "delete", label, ev.Deleted)
	case "importing":
		if ev.Total > 0 {
			bar := progressBar(ev.Current, ev.Total, 24)
			pct := float64(ev.Current) * 100 / float64(ev.Total)
			return fmt.Sprintf("[%s] %5.1f%% %d/%d imported:%d skipped:%d", bar, pct, ev.Current, ev.Total, ev.Imported, ev.Skipped)
		}
		return fmt.Sprintf("[%-10s] %s imported:%d skipped:%d", "import", label, ev.Imported, ev.Skipped)
	default:
		return fmt.Sprintf("[%-10s] %s", ev.Phase, label)
	}
}

func progressBar(current, total, width int) string {
	if width <= 0 {
		width = 24
	}
	if total <= 0 {
		return strings.Repeat("-", width)
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}
	filled := current * width / total
	return strings.Repeat("=", filled) + strings.Repeat("-", width-filled)
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

	fmt.Println("Padix CVE Database Update")
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

	progress := newUpdateProgress(os.Stderr)
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
