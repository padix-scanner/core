// Package httpx provides the HTTP client used by active checks and
// fingerprinting.
//
// Scanning clients must:
//   - accept invalid/expired/self-signed certificates (the scanner reports TLS
//     problems; it must not be blinded by them), and
//   - follow redirects, but only inside the target's own site, so that an
//     http→https or www↔apex redirect does not silently yield empty results.
package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxRedirects bounds how many redirects a client follows for one request.
const MaxRedirects = 5

// minResolveTimeout is the lower bound for the whole redirect chain of
// ResolveOrigin. Shared hosts are often slow on the first request.
const minResolveTimeout = 10 * time.Second

// DefaultPort returns the default port of an http(s) scheme, or 0.
func DefaultPort(scheme string) int {
	switch strings.ToLower(scheme) {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// HostPort returns the authority (host[:port]) for a URL of the given scheme.
// The port is omitted when it is the scheme's default.
//
// This matters: Go sends "Host: example.com:80" when the URL contains an
// explicit :80, browsers do not. Servers that echo the Host header into a
// redirect (RewriteRule ... https://%{HTTP_HOST}/...) then produce a
// redirect to https://example.com:80/ which can never work.
func HostPort(scheme, host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]" // IPv6 literal
	}
	if port == DefaultPort(scheme) {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

// SameSite reports whether a and b point at the same site: same hostname
// (case-insensitive, a leading "www." is ignored), http(s) only. Scheme and
// port may differ, so http://host:80 → https://host is accepted.
func SameSite(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Scheme != "http" && a.Scheme != "https" {
		return false
	}
	return canonicalHost(a.Hostname()) == canonicalHost(b.Hostname())
}

func canonicalHost(h string) string {
	return strings.TrimPrefix(strings.ToLower(h), "www.")
}

// fixRedirectPort repairs redirect targets that carry a bogus port.
//
//  1. A default port for its own scheme (https://host:443/) is dropped.
//  2. If the scheme changed and the port is just the previous URL's default
//     port echoed back (http://host:80/ → https://host:80/), it is dropped.
func fixRedirectPort(next, prev *url.URL) {
	port := next.Port()
	if port == "" {
		return
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return
	}

	drop := n == DefaultPort(next.Scheme)
	if !drop && next.Scheme != prev.Scheme && port == prev.Port() &&
		n == DefaultPort(prev.Scheme) {
		drop = true
	}
	if drop {
		next.Host = HostPort(next.Scheme, next.Hostname(), DefaultPort(next.Scheme))
	}
}

// NewClient returns a client that follows up to MaxRedirects redirects for
// which allow returns true (nil allows every http(s) target). Redirects that
// are refused are not errors: the redirect response itself is returned.
// https → http downgrades are always refused.
func NewClient(timeout time.Duration, allow func(next *url.URL) bool) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS10, // still reach legacy servers
				// #nosec G402 -- intentional: a scanner must connect to hosts with
				// bad certificates; certificate problems are reported separately.
				InsecureSkipVerify: true,
			},
			TLSHandshakeTimeout: timeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return http.ErrUseLastResponse
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			prev := via[len(via)-1].URL
			if prev.Scheme == "https" && req.URL.Scheme == "http" {
				return http.ErrUseLastResponse
			}

			fixRedirectPort(req.URL, prev)
			req.Host = req.URL.Host // keep the Host header in sync with the fixed URL

			if allow != nil && !allow(req.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

var (
	originMu    sync.Mutex
	originCache = make(map[string]url.URL)
)

// ResolveOrigin requests target once, following same-site redirects, and
// returns the origin (scheme://host[:port]/) the site actually serves from.
// Callers use it as the base for the whole assessment.
//
// Successful results are cached per target so that several checks of one scan
// do not repeat the request. A transient failure is retried once. A non-nil
// error means the target could not be reached at all, which callers must
// surface instead of reporting "no findings".
func ResolveOrigin(ctx context.Context, target *url.URL, timeout time.Duration, userAgent string) (*url.URL, error) {
	key := target.String()

	originMu.Lock()
	if cached, ok := originCache[key]; ok {
		originMu.Unlock()
		out := cached
		return &out, nil
	}
	originMu.Unlock()

	if timeout < minResolveTimeout {
		timeout = minResolveTimeout
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		origin, err := resolveOnce(ctx, target, timeout, userAgent)
		if err == nil {
			originMu.Lock()
			originCache[key] = *origin
			originMu.Unlock()
			return origin, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func resolveOnce(ctx context.Context, target *url.URL, timeout time.Duration, userAgent string) (*url.URL, error) {
	client := NewClient(timeout, func(next *url.URL) bool { return SameSite(next, target) })
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", target.Redacted(), err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	final := resp.Request.URL
	return &url.URL{Scheme: final.Scheme, Host: final.Host, Path: "/"}, nil
}