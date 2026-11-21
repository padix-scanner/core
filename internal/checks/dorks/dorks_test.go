package dorks

import (
	"strings"
	"testing"
)

func TestExtractDomainParts(t *testing.T) {
	tests := []struct {
		in     string
		domain string
		sld    string
	}{
		{"example.com", "example.com", "example"},
		{"www.example.com", "www.example.com", "example"},
		{"https://sub.example.co.uk/path", "sub.example.co.uk", "co"},
		{"192.168.1.1", "192.168.1.1", "1"},
		{"", "", ""},
	}

	for _, tt := range tests {
		d, s := extractDomainParts(tt.in)
		if d != tt.domain || s != tt.sld {
			t.Errorf("extractDomainParts(%q) = (%q, %q), want (%q, %q)",
				tt.in, d, s, tt.domain, tt.sld)
		}
	}
}

func TestAssessProducesExpectedCategories(t *testing.T) {
	findings := Assess("example.com")
	if len(findings) != len(templates) {
		t.Fatalf("expected %d findings, got %d", len(templates), len(findings))
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Category != "dorks" {
			t.Errorf("unexpected category %q", f.Category)
		}
		if f.Severity != "info" {
			t.Errorf("unexpected severity %q", f.Severity)
		}
		if !strings.Contains(f.Evidence, "Query:") {
			t.Errorf("evidence missing Query line: %s", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "Google:") {
			t.Errorf("evidence missing Google URL: %s", f.Evidence)
		}
		if seen[f.ID] {
			t.Errorf("duplicate ID %s", f.ID)
		}
		seen[f.ID] = true
	}
}

func TestAssessEmptyTarget(t *testing.T) {
	if got := Assess(""); len(got) != 0 {
		t.Fatalf("expected no findings for empty target, got %d", len(got))
	}
}
