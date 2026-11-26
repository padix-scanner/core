// Package dirlist checks HTTP directories for publicly exposed auto-index pages.
package dirlist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"core/internal/checks/crawl"
	"core/internal/httpx"
	"core/pkg/constants"
	"core/pkg/models"
)

const (
	defaultMaxPages       = 20
	defaultMaxDirectories = 20
	maxBodyBytes          = 512 << 10
)

var commonDirectories = []string{
	"uploads/", "upload/", "files/", "file/", "backup/", "backups/",
	"storage/", "public/", "private/", "documents/", "downloads/",
	"media/", "images/", "tmp/", "temp/", "logs/", "data/",
}

var (
	indexTitleRE  = regexp.MustCompile(`(?is)<title[^>]*>\s*(?:index of|directory listing)\b`)
	indexHeaderRE = regexp.MustCompile(`(?is)<h[1-3][^>]*>\s*(?:index of|directory listing)\b`)
	parentRE      = regexp.MustCompile(`(?is)>\s*(?:\.\./|parent directory)\s*<`)
	columnsRE     = regexp.MustCompile(`(?is)(?:name\s+last modified\s+size|last modified\s+size\s+description)`)
	iisRE         = regexp.MustCompile(`(?is)directory listing\s*[-—]\s*/`)
)

// Config bounds the number and duration of requests made by this assessment.
type Config struct {
	Timeout        time.Duration
	MaxPages       int
	MaxDirectories int
	UserAgent      string
}

func DefaultConfig() Config {
	return Config{
		Timeout:        5 * time.Second,
		MaxPages:       defaultMaxPages,
		MaxDirectories: defaultMaxDirectories,
		UserAgent:      constants.AppUserAgent,
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

// Assess crawls the target and checks a bounded set of common directory paths.
// It only issues GET requests to the origin the target serves from (after
// following same-site redirects such as http→https).
func Assess(ctx context.Context, target string, cfg Config) ([]models.Finding, error) {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" ||
		(base.Scheme != "http" && base.Scheme != "https") || base.User != nil {
		return nil, fmt.Errorf("invalid assessment URL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxPages <= 0 || cfg.MaxPages > 100 {
		cfg.MaxPages = defaultMaxPages
	}
	if cfg.MaxDirectories <= 0 || cfg.MaxDirectories > 100 {
		cfg.MaxDirectories = defaultMaxDirectories
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = constants.AppUserAgent
	}

	// Follow same-site redirects once up front and use the origin the site
	// really serves from. An unreachable target is an error, not "no findings".
	origin, err := httpx.ResolveOrigin(ctx, base, cfg.Timeout, cfg.UserAgent)
	if err != nil {
		return nil, err
	}
	base = origin

	s := &scanner{
		cfg: cfg, origin: origin,
		client: httpx.NewClient(cfg.Timeout, func(next *url.URL) bool {
			return crawl.SameOrigin(next, origin)
		}),
	}
	defer s.client.CloseIdleConnections()

	seen := make(map[string]struct{})
	var findings []models.Finding
	var directories []*url.URL

	// Crawl reachable same-origin pages. Directory links are queued for an
	// explicit check too, including links whose listing is not linked from root.
	err = crawl.Crawl(ctx, base, cfg.MaxPages, s.fetch, func(page *url.URL, body string) error {
		if f := s.inspect(page, body); f != nil {
			findings = append(findings, *f)
		}
		for _, raw := range crawl.ExtractLinks(body) {
			next := crawl.Resolve(page, raw)
			if next == nil || !crawl.SameOrigin(next, base) || !strings.HasSuffix(next.Path, "/") {
				continue
			}
			key := crawl.Canonical(next)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if len(directories) < cfg.MaxDirectories {
				directories = append(directories, next)
			}
		}
		return nil
	})
	if err != nil {
		return deduplicate(findings), err
	}

	// Probe common paths even when the application does not link to them.
	for _, path := range commonDirectories {
		if len(directories) >= cfg.MaxDirectories {
			break
		}
		u := *base
		prefix := strings.TrimRight(base.Path, "/")
		u.Path = prefix + "/" + path
		u.RawPath = ""
		key := crawl.Canonical(&u)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		directories = append(directories, &u)
	}

	for _, directory := range directories {
		if err := ctx.Err(); err != nil {
			return deduplicate(findings), err
		}
		if !crawl.SameOrigin(directory, base) {
			continue
		}
		body, err := s.fetch(ctx, directory)
		if err != nil {
			continue
		}
		if f := s.inspect(directory, body); f != nil {
			findings = append(findings, *f)
		}
	}

	return deduplicate(findings), nil
}

func (s *scanner) fetch(ctx context.Context, u *url.URL) (string, error) {
	if !crawl.SameOrigin(u, s.origin) {
		return "", fmt.Errorf("cross-origin request blocked")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType != "" && !strings.Contains(contentType, "text/html") &&
		!strings.Contains(contentType, "text/plain") && !strings.Contains(contentType, "application/xhtml+xml") {
		return "", fmt.Errorf("not an HTML or text response")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(body), err
}

// isDirectoryListing requires multiple independent auto-index indicators to
// avoid flagging ordinary pages that merely contain the words "index of".
func isDirectoryListing(body string) bool {
	lower := strings.ToLower(body)
	title := indexTitleRE.MatchString(lower)
	header := indexHeaderRE.MatchString(lower)
	parent := parentRE.MatchString(lower)
	columns := columnsRE.MatchString(lower)
	iis := iisRE.MatchString(lower)

	if iis && (parent || columns) {
		return true
	}
	if (title || header) && (parent || columns) {
		return true
	}
	// Some minimal auto-index templates omit a title but expose both a parent
	// link and the characteristic file-list column headings.
	return parent && columns
}

func (s *scanner) inspect(u *url.URL, body string) *models.Finding {
	if !isDirectoryListing(body) {
		return nil
	}
	return &models.Finding{
		ID:          "directory-listing-" + safeID(u.Host+u.Path),
		Title:       "Directory listing enabled",
		Category:    "directory-listing",
		Severity:    "medium",
		Status:      "vulnerable",
		Confidence:  "high",
		Description: "The web server exposes an automatically generated directory index. Visitors may be able to enumerate and download files that are not otherwise linked by the application. Disable directory indexing or restrict access to the affected path.",
		Evidence:    fmt.Sprintf("URL: %s\nHTTP status: 200\nEvidence: recognizable directory-index page markers detected", u.Redacted()),
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

func deduplicate(in []models.Finding) []models.Finding {
	seen := make(map[string]struct{}, len(in))
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		out = append(out, f)
	}
	return out
}