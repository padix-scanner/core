// Package sensitive probes a fixed, bounded list of well-known paths that
// should never be public (.env, .git, backups, debug pages, ...).
//
// Only same-origin GET requests with a Range header are sent. A hit requires
// a content signature, not just HTTP 200, and file contents are never copied
// into findings.
package sensitive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"core/internal/checks/crawl"
	"core/internal/httpx"
	"core/pkg/constants"
	"core/pkg/models"
)

// maxBodyBytes is enough for every signature; large archives are never
// downloaded in full.
const maxBodyBytes = 64 << 10

// Config bounds the assessment.
type Config struct {
	Timeout   time.Duration
	UserAgent string
}

func DefaultConfig() Config {
	return Config{
		Timeout:   5 * time.Second,
		UserAgent: constants.AppUserAgent,
	}
}

type response struct {
	status      int
	contentType string
	body        string
}

type scanner struct {
	cfg    Config
	origin *url.URL
	client *http.Client
}

// baseline is the response the site gives for a path that cannot exist. When
// a site answers 200 for everything, matching bodies are discarded.
type baseline struct{ body string }

func (b *baseline) matches(body string) bool {
	if b == nil {
		return false
	}
	if body == b.body {
		return true
	}
	la, lb := len(body), len(b.body)
	if la == 0 || lb == 0 {
		return false
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	if diff*50 > lb { // more than ~2% different in size
		return false
	}
	n := min(256, la, lb)
	return body[:n] == b.body[:n]
}

// Assess requests each rule's path and reports those whose response matches
// the file's signature.
func Assess(ctx context.Context, target string, cfg Config) ([]models.Finding, error) {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" ||
		(base.Scheme != "http" && base.Scheme != "https") || base.User != nil {
		return nil, fmt.Errorf("invalid assessment URL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = constants.AppUserAgent
	}

	// An unreachable target is an error, not "no findings".
	origin, err := httpx.ResolveOrigin(ctx, base, cfg.Timeout, cfg.UserAgent)
	if err != nil {
		return nil, err
	}

	s := &scanner{
		cfg:    cfg,
		origin: origin,
		client: httpx.NewClient(cfg.Timeout, func(next *url.URL) bool {
			return crawl.SameOrigin(next, origin)
		}),
	}
	defer s.client.CloseIdleConnections()

	catchAll := s.catchAllBaseline(ctx)

	var findings []models.Finding
	for _, r := range rules {
		if err := ctx.Err(); err != nil {
			return findings, err
		}

		u := s.urlFor(r.Path)
		resp, err := s.get(ctx, u)
		if err != nil {
			continue
		}
		if resp.status != http.StatusOK && resp.status != http.StatusPartialContent {
			continue
		}
		if catchAll.matches(resp.body) {
			continue
		}
		marker, ok := r.Validate(resp)
		if !ok {
			continue
		}

		findings = append(findings, buildFinding(r, u, resp, marker))
	}

	return findings, nil
}

// catchAllBaseline requests a random, non-existent path. It returns nil when
// the site correctly answers with a non-2xx status.
func (s *scanner) catchAllBaseline(ctx context.Context) *baseline {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil
	}
	resp, err := s.get(ctx, s.urlFor("/padix-"+hex.EncodeToString(buf[:])+"-nf"))
	if err != nil {
		return nil
	}
	if resp.status == http.StatusOK || resp.status == http.StatusPartialContent {
		return &baseline{body: resp.body}
	}
	return nil
}

func (s *scanner) urlFor(path string) *url.URL {
	u := *s.origin
	u.Path = path
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return &u
}

func (s *scanner) get(ctx context.Context, u *url.URL) (response, error) {
	if !crawl.SameOrigin(u, s.origin) {
		return response{}, fmt.Errorf("cross-origin request blocked")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxBodyBytes-1))

	resp, err := s.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return response{
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		body:        string(body),
	}, err
}

func buildFinding(r rule, u *url.URL, resp response, marker string) models.Finding {
	confidence := r.Confidence
	if confidence == "" {
		confidence = "high"
	}
	contentType := resp.contentType
	if contentType == "" {
		contentType = "N/A"
	}

	return models.Finding{
		ID:          "sensitive-file-" + safeID(u.Host+u.Path),
		Title:       r.Title,
		Category:    "sensitive-files",
		Severity:    r.Severity,
		Status:      "vulnerable",
		Confidence:  confidence,
		Description: r.Description,
		Evidence: fmt.Sprintf(
			"URL: %s\nHTTP status: %d\nContent-Type: %s\nBytes read: %d\nMatched: %s\nNote: file contents are intentionally not stored in this report.",
			u.Redacted(), resp.status, contentType, len(resp.body), marker,
		),
	}
}

func safeID(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}