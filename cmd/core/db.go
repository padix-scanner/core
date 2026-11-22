package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"core/internal/terminal"
	"core/internal/vulnerability/cvedb"
	"core/internal/vulnerability/source"
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

	db, err := cvedb.OpenDB(ctx, *dbPath)
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

func runDBUpdate(args []string) error {
	flags := flag.NewFlagSet("db update", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	dbPath := flags.String(
		"db",
		constants.DefaultCVEDatabasePath,
		"SQLite database path",
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

	fmt.Fprintf(os.Stderr, "%s CVE Database Update\n", constants.AppName)
	fmt.Fprintf(os.Stderr, "Database: %s\n", *dbPath)

	db, err := cvedb.OpenDB(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	sourceManager := source.NewSourceManager(
		db.GORM(),
		source.UpdaterConfig{
			CacheDir: *cacheDir,
		},
	)

	progress := terminal.NewUpdateProgress()
	summary, err := sourceManager.Update(
		ctx,
		source.UpdateOptions{
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

/**************************************/
/**************************************/
/**************************************/

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
