package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"core/internal/vulnerability/cvedb"
	"core/pkg/models"
)

// captureStdout runs fn with os.Stdout redirected and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	fn()

	_ = w.Close()
	os.Stdout = old
	return <-done
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"http://example.com":       "example.com",
		"https://example.com":      "example.com",
		"  example.com  ":          "example.com",
		"example.com/":             "example.com",
		"example.com:8080":         "example.com",
		"192.168.1.10":             "192.168.1.10",
		"https://example.com/path": "example.com/path",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.co.uk",
		"192.168.1.10",
		"::1",
		"a-b.example.com",
	}
	for _, v := range valid {
		if err := validateTarget(v); err != nil {
			t.Errorf("validateTarget(%q) unexpected error: %v", v, err)
		}
	}

	invalid := []string{
		"",
		"example",             // no suffix
		"example.com/path",    // path
		"example.com?q=1",     // query
		"user@example.com",    // @
		"-bad.example.com",    // leading hyphen
		"bad-.example.com",    // trailing hyphen
		"exa mple.com",        // space
		strings.Repeat("a", 254), // too long
	}
	for _, v := range invalid {
		if err := validateTarget(v); err == nil {
			t.Errorf("validateTarget(%q) expected error, got nil", v)
		}
	}
}

func TestDescribeOS(t *testing.T) {
	cases := []struct {
		host models.Host
		want string
	}{
		{models.Host{}, "N/A"},
		{models.Host{OS: "Linux"}, "Linux"},
		{models.Host{OS: "Linux", OSVersion: "22.04"}, "Linux (22.04)"},
		{models.Host{OS: "Linux", OSConfidence: "high"}, "Linux, confidence high"},
		{models.Host{OS: "Linux", OSVersion: "22.04", OSConfidence: "high"}, "Linux (22.04), confidence high"},
	}
	for _, c := range cases {
		if got := describeOS(c.host); got != c.want {
			t.Errorf("describeOS(%+v) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		0:          "0 B",
		512:        "512 B",
		1024:       "1.0 KiB",
		1536:       "1.5 KiB",
		1048576:    "1.0 MiB",
		1073741824: "1.0 GiB",
	}
	for n, want := range cases {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestDefaultDBStatusValue(t *testing.T) {
	if got := defaultDBStatusValue("", "never"); got != "never" {
		t.Errorf("empty = %q", got)
	}
	if got := defaultDBStatusValue("  ", "-"); got != "-" {
		t.Errorf("blank = %q", got)
	}
	if got := defaultDBStatusValue("success", "-"); got != "success" {
		t.Errorf("value = %q", got)
	}
}

func TestPrintUsage(t *testing.T) {
	out := captureStdout(t, printUsage)
	for _, want := range []string{"Usage:", "scan", "db", "version", "Scan Options:", "Db sub commands:"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output missing %q", want)
		}
	}
}

func TestPrintBanner(t *testing.T) {
	out := captureStdout(t, printBanner)
	if !strings.Contains(out, "Padix") {
		t.Errorf("banner missing app name: %q", out)
	}
}

func TestRunDBMissingSubcommand(t *testing.T) {
	err := runDB(nil)
	if err == nil || !strings.Contains(err.Error(), "missing database subcommand") {
		t.Errorf("err = %v", err)
	}
}

func TestRunDBUnknownSubcommand(t *testing.T) {
	err := runDB([]string{"bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown database command") {
		t.Errorf("err = %v", err)
	}
}

func TestRunDBStatusMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.db")
	// Should not error: a missing DB is reported as "missing".
	out := captureStdout(t, func() {
		if err := runDBStatus([]string{"--db", missing}); err != nil {
			t.Errorf("runDBStatus: %v", err)
		}
	})
	if !strings.Contains(out, "missing") {
		t.Errorf("output missing status: %q", out)
	}
}

func TestRunDBStatusReady(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cve.db")
	db, err := cvedb.OpenDB(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runDBStatus([]string{"--db", path}); err != nil {
			t.Errorf("runDBStatus: %v", err)
		}
	})
	for _, want := range []string{"Status:   ready", "CVEs:", "Products:", "Sync:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %q", want, out)
		}
	}
}

func TestRunDBStatusExtraArgs(t *testing.T) {
	err := runDBStatus([]string{"extra"})
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("err = %v", err)
	}
}

func TestRunDBUpdateExtraArgs(t *testing.T) {
	err := runDBUpdate([]string{"extra"})
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("err = %v", err)
	}
}

func TestAppConstants(t *testing.T) {
	if appCommandName != "padix" {
		t.Errorf("appCommandName = %q", appCommandName)
	}
	if appName == "" || appVersion == "" || appUserAgent == "" {
		t.Error("app constants should not be empty")
	}
}