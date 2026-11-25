package crawl

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestExtractLinksFindsHrefs(t *testing.T) {
	body := `<html><body>
	<a href="/page1">Page 1</a>
	<a href="https://example.com/page2">Page 2</a>
	<a href="#section">Section</a>
	<a href="mailto:test@example.com">Mail</a>
	</body></html>`

	links := ExtractLinks(body)
	if len(links) != 3 {
		t.Fatalf("expected 3 links, got %d: %v", len(links), links)
	}
}

func TestExtractLinksEmptyReturnsNil(t *testing.T) {
	if links := ExtractLinks(""); len(links) != 0 {
		t.Fatalf("expected empty slice, got %v", links)
	}
}

func TestCanonicalStripsFragment(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?q=1#frag")
	got := Canonical(u)
	if strings.Contains(got, "#") {
		t.Fatalf("expected fragment stripped: %s", got)
	}
}

func TestResolveResolvesRelative(t *testing.T) {
	base, _ := url.Parse("http://example.com/dir/")
	u := Resolve(base, "page.html")
	if u == nil {
		t.Fatal("expected non-nil resolved URL")
	}
	if u.String() != "http://example.com/dir/page.html" {
		t.Fatalf("unexpected resolution: %s", u.String())
	}
}

func TestResolveRejectsFragmentAndInvalidScheme(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	if u := Resolve(base, "ftp://other.com/"); u != nil {
		t.Fatal("expected nil for ftp scheme")
	}
	if u := Resolve(base, "#frag"); u == nil || u.String() != "http://example.com/" {
		t.Fatalf("expected base URL for fragment-only link, got %v", u)
	}
}

func TestSameOriginMatches(t *testing.T) {
	a, _ := url.Parse("https://example.com/path")
	b, _ := url.Parse("https://example.com/other")
	if !SameOrigin(a, b) {
		t.Fatal("expected same origin")
	}
}

func TestSameOriginRejectsDifferentSchemeHostAndUserinfo(t *testing.T) {
	a, _ := url.Parse("https://example.com/")
	b, _ := url.Parse("http://example.com/")
	if SameOrigin(a, b) {
		t.Fatal("expected different scheme to be rejected")
	}

	c, _ := url.Parse("https://other.com/")
	if SameOrigin(a, c) {
		t.Fatal("expected different host to be rejected")
	}

	d, _ := url.Parse("https://user:pass@example.com/")
	if SameOrigin(d, a) {
		t.Fatal("expected userinfo to be rejected")
	}
}

func TestCrawlVisitsPagesUpToMaxPages(t *testing.T) {
	var visited []string
	fetch := func(ctx context.Context, u *url.URL) (string, error) {
		visited = append(visited, u.String())
		return `<html><a href="/next">next</a></html>`, nil
	}
	origin, _ := url.Parse("http://example.com/")

	err := Crawl(context.Background(), origin, 2, fetch, func(u *url.URL, body string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visited) != 2 {
		t.Fatalf("expected 2 pages visited, got %d: %v", len(visited), visited)
	}
}

func TestCrawlStopsOnVisitError(t *testing.T) {
	boom := errors.New("boom")
	fetch := func(ctx context.Context, u *url.URL) (string, error) {
		return `<html><a href="/next">next</a></html>`, nil
	}
	origin, _ := url.Parse("http://example.com/")

	err := Crawl(context.Background(), origin, 10, fetch, func(u *url.URL, body string) error {
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("expected visit error propagated, got %v", err)
	}
}

func TestCrawlRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetch := func(ctx context.Context, u *url.URL) (string, error) {
		return "ok", nil
	}
	origin, _ := url.Parse("http://example.com/")

	err := Crawl(ctx, origin, 10, fetch, func(u *url.URL, body string) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}
