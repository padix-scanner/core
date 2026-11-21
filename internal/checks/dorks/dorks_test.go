package dorks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	// Generation-only path (no network).
	cfg := DefaultConfig()
	cfg.Request = false

	findings := Assess(context.Background(), "example.com", cfg)
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
	cfg := DefaultConfig()
	cfg.Request = false
	if got := Assess(context.Background(), "", cfg); len(got) != 0 {
		t.Fatalf("expected no findings for empty target, got %d", len(got))
	}
}

func TestParseDuckDuckGoLite(t *testing.T) {
	html := `
<html><body>
<a href="https://example.com/backup.zip">backup</a>
<a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fsub.example.com%2Fsecret">wrapped</a>
<a href="https://duckduckgo.com/about">self</a>
<a href="/relative">rel</a>
</body></html>`

	got := parseDuckDuckGoLite(html)
	if len(got) < 2 {
		t.Fatalf("expected at least 2 links, got %#v", got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "https://example.com/backup.zip") {
		t.Errorf("missing direct link: %s", joined)
	}
	if !strings.Contains(joined, "https://sub.example.com/secret") {
		t.Errorf("missing unwrapped redirect: %s", joined)
	}
	if strings.Contains(joined, "duckduckgo.com/about") {
		t.Errorf("should filter self links: %s", joined)
	}
}

func TestFilterRelevant(t *testing.T) {
	links := []string{
		"https://example.com/a",
		"https://sub.example.com/b",
		"https://other.com/c",
		"https://github.com/org/example-repo",
		"https://pastebin.com/xyz",
	}
	got := filterRelevant(links, "example.com", "example")
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "example.com/a") || !strings.Contains(joined, "sub.example.com") {
		t.Fatalf("expected target domain links: %s", joined)
	}
	if !strings.Contains(joined, "github.com") {
		t.Fatalf("expected github hit mentioning target: %s", joined)
	}
	if strings.Contains(joined, "other.com") {
		t.Fatalf("should drop unrelated host: %s", joined)
	}
}

func TestRequestDuckDuckGoLiteMock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<a href="https://example.com/secret.bak">hit</a>
			<a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.example.com%2Fconfig.env">wrapped</a>
		`))
	}))
	defer ts.Close()

	// Temporarily point the requester at the test server by calling the
	// parser path directly (full requestDuckDuckGoLite hard-codes the host).
	// Exercise the HTTP path via a local client against the mock.
	client := ts.Client()
	cfg := DefaultConfig()
	cfg.Timeout = time.Second

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/?q=test", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	links := parseDuckDuckGoLite(string(body[:n]))
	if len(links) == 0 {
		t.Fatal("expected parsed links from mock response")
	}
}
