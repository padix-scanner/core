package reporter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateReportTextToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")
	if ok := GenerateReport(path, "text", sampleResult()); !ok {
		t.Fatal("GenerateReport returned false")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("report file is empty")
	}
}

func TestGenerateReportJSONToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if ok := GenerateReport(path, "json", sampleResult()); !ok {
		t.Fatal("GenerateReport returned false")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("report file is empty")
	}
}

func TestGenerateReportJSONRequiresFile(t *testing.T) {
	if ok := GenerateReport("", "json", sampleResult()); ok {
		t.Fatal("expected false when JSON has no output file")
	}
}

func TestGenerateReportInvalidPath(t *testing.T) {
	// A path whose parent is a file, not a directory, cannot be created.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok := GenerateReport(filepath.Join(blocker, "report.txt"), "text", sampleResult()); ok {
		t.Fatal("expected false for unwritable path")
	}
}