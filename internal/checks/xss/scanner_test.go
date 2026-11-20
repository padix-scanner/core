package xss

import (
	"context"
	"core/internal/checks/crawl"
	"core/pkg/models"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAssessDetectsReflectedXSS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if v := q.Get("q"); strings.Contains(v, "<script>") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>You searched for: ` + v + `</body></html>`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/search?q=1">item</a>`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	s := newTestScanner(u)
	got, err := s.assess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Category != "xss" {
		t.Fatalf("expected XSS finding, got %#v", got)
	}
}

func TestSameOriginBlocksExternalHost(t *testing.T) {
	base, _ := url.Parse("https://example.test/")
	external, _ := url.Parse("https://other.test/")
	if crawl.SameOrigin(external, base) {
		t.Fatal("cross-origin URL must be rejected")
	}
}

func parseTestURL(raw string) (*url.URL, error) { return url.Parse(raw) }

func newTestScanner(base *url.URL) *scanner {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	return &scanner{
		cfg:    cfg,
		origin: base,
		client: &http.Client{
			Timeout:       time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (s *scanner) assess(ctx context.Context) ([]models.Finding, error) {
	var results []models.Finding
	err := crawl.Crawl(ctx, s.origin, 10, s.fetch, func(u *url.URL, body string) error {
		if len(u.Query()) > 0 {
			results = append(results, s.testURL(ctx, u)...)
		}
		return nil
	})
	if err != nil {
		return results, err
	}
	return deduplicate(results), nil
}
