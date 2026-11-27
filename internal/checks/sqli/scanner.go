package sqli

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
	maxBodyBytes = 512 << 10
	maxPages     = 20
	maxParams    = 8
)

var sqlErrors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)mysql_fetch|mysqli?_`),
	regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
	regexp.MustCompile(`(?i) PostgreSQL.*ERROR|ERROR:\s+syntax error`),
	regexp.MustCompile(`(?i)Microsoft SQL Server|ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)ORA-\d{5}`),
	regexp.MustCompile(`(?i)SQLite/JDBCDriver|SQLite.Exception|SQLITE_ERROR`),
}

// Config bounds the active assessment. Only same-origin HTTP GET requests are sent.
type Config struct {
	Timeout       time.Duration
	MaxPages      int
	MaxParameters int
	UserAgent     string
}

func DefaultConfig() Config {
	return Config{
		Timeout:       5 * time.Second,
		MaxPages:      maxPages,
		MaxParameters: maxParams,
		UserAgent:     constants.AppUserAgent,
	}
}

type response struct {
	status int
	body   string
}

type scanner struct {
	client *http.Client
	cfg    Config
	origin *url.URL
}

func Assess(ctx context.Context, target string, cfg Config) ([]models.Finding, error) {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("invalid assessment URL")
	}
	if base.User != nil {
		return nil, fmt.Errorf("URL userinfo is not allowed")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxPages <= 0 || cfg.MaxPages > 100 {
		cfg.MaxPages = maxPages
	}
	if cfg.MaxParameters <= 0 || cfg.MaxParameters > 32 {
		cfg.MaxParameters = maxParams
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = constants.AppUserAgent
	}

	// Follow same-site redirects (http→https, www↔apex, ...) once up front and
	// use the origin the site really serves from for the whole assessment.
	// An unreachable target is an error, not an empty result.
	origin, err := httpx.ResolveOrigin(ctx, base, cfg.Timeout, cfg.UserAgent)
	if err != nil {
		return nil, err
	}

	// The CLI caller must only invoke active checks for an explicitly authorized target.
	s := &scanner{
		cfg:    cfg,
		origin: origin,
		client: httpx.NewClient(cfg.Timeout, func(next *url.URL) bool {
			return crawl.SameOrigin(next, origin)
		}),
	}
	defer s.client.CloseIdleConnections()

	var results []models.Finding
	err = crawl.Crawl(ctx, origin, cfg.MaxPages, s.fetch, func(u *url.URL, body string) error {
		if len(u.Query()) > 0 {
			results = append(results, s.testURL(ctx, u)...)
		}
		for _, formURL := range crawl.ExtractGETForms(u, body) {
			if len(formURL.Query()) > 0 {
				results = append(results, s.testURL(ctx, formURL)...)
			}
		}
		return nil
	})
	return deduplicate(results), err
}

// fetch is the crawl Fetcher. In-origin redirects were already followed by
// the client; a remaining non-2xx means there is nothing to crawl.
func (s *scanner) fetch(ctx context.Context, u *url.URL) (string, error) {
	resp, err := s.get(ctx, u)
	if err != nil {
		return "", err
	}
	if resp.status < 200 || resp.status >= 300 {
		return "", fmt.Errorf("non-2xx status: %d", resp.status)
	}
	return resp.body, nil
}

func (s *scanner) testURL(ctx context.Context, target *url.URL) []models.Finding {
	query := target.Query()
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	if len(keys) > s.cfg.MaxParameters {
		keys = keys[:s.cfg.MaxParameters]
	}
	var out []models.Finding
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			break
		}
		original := query.Get(key)
		if len(original) > 256 {
			continue
		}

		// Error-based: a quote is a low-impact syntax perturbation. Report only
		// when the response exposes a recognizable database error signature.
		errorURL := cloneURL(target)
		q := errorURL.Query()
		q.Set(key, original+"'")
		errorURL.RawQuery = q.Encode()
		errorResp, err := s.get(ctx, errorURL)
		if err == nil && databaseError(errorResp.body) {
			out = append(out, finding("error", errorURL, key,
				"Potential SQL injection: database error disclosure",
				"high", "high",
				"The parameter caused a recognizable database error response. Confirm manually in an authorized test environment.",
				"Database error signature detected in response"))
			continue
		}

		// Boolean-based: compare paired predicates while keeping the rest of
		// the request constant. This is differential evidence, not proof alone.
		trueURL, falseURL := cloneURL(target), cloneURL(target)
		tq, fq := trueURL.Query(), falseURL.Query()
		tq.Set(key, original+"' AND '1'='1")
		fq.Set(key, original+"' AND '1'='2")
		trueURL.RawQuery, falseURL.RawQuery = tq.Encode(), fq.Encode()
		tr, te := s.get(ctx, trueURL)
		fr, fe := s.get(ctx, falseURL)
		if te == nil && fe == nil && tr.status == fr.status && meaningfulDifference(tr.body, fr.body) {
			out = append(out, finding("boolean", target, key,
				"Potential SQL injection: boolean response differential",
				"medium", "medium",
				"Paired true/false SQL predicates produced materially different response bodies. Dynamic pages can cause false positives; manual verification is required.",
				fmt.Sprintf("True predicate: HTTP %d, %d bytes; false predicate: HTTP %d, %d bytes",
					tr.status, len(tr.body), fr.status, len(fr.body))))
		}
	}
	return out
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
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	resp, err := s.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return response{status: resp.StatusCode, body: string(body)}, err
}

func cloneURL(u *url.URL) *url.URL {
	v := *u
	return &v
}

func databaseError(body string) bool {
	for _, pattern := range sqlErrors {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

func meaningfulDifference(a, b string) bool {
	if a == b {
		return false
	}
	// Require a substantial size delta to avoid reporting tiny nonce/timestamp changes.
	longest := len(a)
	if len(b) > longest {
		longest = len(b)
	}
	if longest < 80 {
		return false
	}
	delta := len(a) - len(b)
	if delta < 0 {
		delta = -delta
	}
	return float64(delta)/float64(longest) >= 0.30
}

func finding(kind string, u *url.URL, parameter, title, severity, confidence, description, evidence string) models.Finding {
	return models.Finding{
		ID:          "sqli-" + kind + "-" + safeID(u.Host+u.Path+"-"+parameter),
		Title:       title,
		Category:    "sql-injection",
		Severity:    severity,
		Status:      "potential",
		Confidence:  confidence,
		Description: description,
		Evidence:    fmt.Sprintf("URL: %s\nParameter: %s\n%s", u.Redacted(), parameter, evidence),
	}
}

func safeID(v string) string {
	v = strings.ToLower(v)
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
			b.WriteByte('-')
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
