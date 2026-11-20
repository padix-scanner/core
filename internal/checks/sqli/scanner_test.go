package sqli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"core/pkg/models"
	"strings"
	"testing"
	"time"
)

func TestAssessDetectsDatabaseError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			http.Error(w, "You have an error in your SQL syntax; check the manual for MySQL", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/item?id=1">item</a>`))
	}))
	defer ts.Close()

	// httptest uses loopback; unit tests exercise scanner internals through a
	// test-only constructor rather than relaxing production private-IP policy.
	u, _ := parseTestURL(ts.URL)
	s := newTestScanner(u)
	got, err := s.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Category != "sql-injection" {
		t.Fatalf("expected SQL injection finding, got %#v", got)
	}
}

func TestExtractGETFormsSkipsPOST(t *testing.T) {
	page, _ := parseTestURL("https://example.test/search")
	body := `<form method="get" action="/find"><input name="q" value="x"></form>
<form method="post" action="/login"><input name="user"></form>`
	got := extractGETForms(page, body)
	if len(got) != 1 || got[0].Path != "/find" || got[0].Query().Get("q") != "x" {
		t.Fatalf("unexpected GET forms: %#v", got)
	}
}

func TestSameOriginBlocksExternalHost(t *testing.T) {
	base, _ := parseTestURL("https://example.test/")
	s := &scanner{origin: base}
	external, _ := parseTestURL("https://other.test/")
	if s.sameOrigin(external) {
		t.Fatal("cross-origin URL must be rejected")
	}
}

func parseTestURL(raw string) (*url.URL, error) { return url.Parse(raw) }

func newTestScanner(base *url.URL) *scanner {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	return &scanner{
		cfg: cfg, origin: base, visited: map[string]struct{}{}, findings: map[string]struct{}{},
		client: &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (s *scanner) run(ctx context.Context) ([]models.Finding, error) {
	queue := []*url.URL{s.origin}
	var results []models.Finding
	for len(queue) > 0 && len(s.visited) < 10 {
		u := queue[0]
		queue = queue[1:]
		if !s.sameOrigin(u) { continue }
		key := canonical(u)
		if _, ok := s.visited[key]; ok { continue }
		s.visited[key] = struct{}{}
		if len(u.Query()) > 0 { results = append(results, s.testURL(ctx, u)...)}
		resp, err := s.get(ctx, u)
		if err != nil { continue }
		for _, link := range extractLinks(resp.body) {
			if next := resolve(u, link); next != nil && s.sameOrigin(next) { queue = append(queue, next) }
		}
	}
	return deduplicate(results), nil
}
