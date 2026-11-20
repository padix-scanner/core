package crawl

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

var hrefRE = regexp.MustCompile(`(?is)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']`)

// Fetcher returns the body for a URL. A non-nil error skips the page.
type Fetcher func(ctx context.Context, u *url.URL) (body string, err error)

// Visit is invoked for each successfully fetched, same-origin page.
type Visit func(u *url.URL, body string) error

// Crawl performs a same-origin breadth-first crawl from origin, stopping
// after maxPages pages or when ctx is cancelled.
func Crawl(
	ctx context.Context,
	origin *url.URL,
	maxPages int,
	fetch Fetcher,
	visit Visit,
) error {
	visited := make(map[string]struct{})
	queue := []*url.URL{origin}
	for len(queue) > 0 && len(visited) < maxPages {
		if err := ctx.Err(); err != nil {
			return err
		}
		u := queue[0]
		queue = queue[1:]
		if !SameOrigin(u, origin) {
			continue
		}
		key := Canonical(u)
		if _, ok := visited[key]; ok {
			continue
		}
		visited[key] = struct{}{}
		body, err := fetch(ctx, u)
		if err != nil {
			continue
		}
		if err := visit(u, body); err != nil {
			return err
		}
		for _, link := range ExtractLinks(body) {
			next := Resolve(u, link)
			if next != nil && SameOrigin(next, origin) && len(visited)+len(queue) < maxPages {
				queue = append(queue, next)
			}
		}
	}
	return nil
}

// SameOrigin reports whether u shares the scheme and host of origin.
func SameOrigin(u, origin *url.URL) bool {
	return u != nil && strings.EqualFold(u.Scheme, origin.Scheme) &&
		strings.EqualFold(u.Host, origin.Host) && u.User == nil
}

// ExtractLinks returns the href values found in the HTML body.
func ExtractLinks(body string) []string {
	matches := hrefRE.FindAllStringSubmatch(body, 50)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// Resolve parses raw relative to base and returns an http(s) URL without a fragment.
func Resolve(base *url.URL, raw string) *url.URL {
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	u := base.ResolveReference(ref)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	u.Fragment = ""
	return u
}

// Canonical returns the URL string without its fragment.
func Canonical(u *url.URL) string {
	v := *u
	v.Fragment = ""
	return v.String()
}
