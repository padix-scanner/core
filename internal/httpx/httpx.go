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
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxRedirects bounds how many redirects a client follows for one request.
const MaxRedirects = 5

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
			if allow != nil && !allow(req.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// ResolveOrigin requests target once, following same-site redirects, and
// returns the origin (scheme://host[:port]/) the site actually serves from.
// Callers use it as the base for the whole assessment.
//
// A non-nil error means the target could not be reached at all, which callers
// must surface instead of reporting "no findings".
func ResolveOrigin(ctx context.Context, target *url.URL, timeout time.Duration, userAgent string) (*url.URL, error) {
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