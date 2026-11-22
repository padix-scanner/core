package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"core/internal/vulnerability"
	"core/pkg/constants"
)

func runDB(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(
			"missing database subcommand; usage: %s db update [options]",
			appCommandName,
		)
	}

	switch args[0] {
	case "update":
		return runDBUpdate(args[1:])
	default:
		return fmt.Errorf(
			"unknown database command %q; available command: update",
			args[0],
		)
	}
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

	summary, err := updater.Update(
		ctx,
		sources,
		vulnerability.UpdateOptions{
			Incremental: *incremental,
		},
	)
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
