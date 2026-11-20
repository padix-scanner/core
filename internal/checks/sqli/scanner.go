package sqli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"core/pkg/constants"
	"core/pkg/models"
)

const (
	maxBodyBytes = 512 << 10
	maxPages     = 20
	maxParams    = 8
)

var (
	hrefRE  = regexp.MustCompile(`(?is)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']`)
	formRE  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
	inputRE = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	attrRE  = regexp.MustCompile(`(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*["']([^"']*)["']`)
	sqlErrors = []*regexp.Regexp{
		regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
		regexp.MustCompile(`(?i)mysql_fetch|mysqli?_`),
		regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
		regexp.MustCompile(`(?i) PostgreSQL.*ERROR|ERROR:\s+syntax error`),
		regexp.MustCompile(`(?i)Microsoft SQL Server|ODBC SQL Server Driver`),
		regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
		regexp.MustCompile(`(?i)ORA-\d{5}`),
		regexp.MustCompile(`(?i)SQLite/JDBCDriver|SQLite.Exception|SQLITE_ERROR`),
	}
)

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
	client  *http.Client
	cfg     Config
	origin  *url.URL
	visited map[string]struct{}
	findings map[string]struct{}
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

// The CLI caller must only invoke active checks for an explicitly authorized target.
	s := &scanner{
		cfg: cfg, origin: base,
		visited: make(map[string]struct{}),
		findings: make(map[string]struct{}),
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: cfg.Timeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	defer s.client.CloseIdleConnections()

	queue := []*url.URL{base}
	var results []models.Finding
	for len(queue) > 0 && len(s.visited) < cfg.MaxPages {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		u := queue[0]
		queue = queue[1:]
		if !s.sameOrigin(u) {
			continue
		}
		key := canonical(u)
		if _, ok := s.visited[key]; ok {
			continue
		}
		s.visited[key] = struct{}{}

		// Test existing query parameters before crawling links.
		if len(u.Query()) > 0 {
			results = append(results, s.testURL(ctx, u)...)
		}
		resp, err := s.get(ctx, u)
		if err != nil || resp.status < 200 || resp.status >= 400 {
			continue
		}
		for _, link := range extractLinks(resp.body) {
			next := resolve(u, link)
			if next != nil && s.sameOrigin(next) && len(s.visited)+len(queue) < cfg.MaxPages {
				queue = append(queue, next)
			}
		}
		for _, formURL := range extractGETForms(u, resp.body) {
			if len(formURL.Query()) > 0 {
				results = append(results, s.testURL(ctx, formURL)...)
			}
		}
	}
	return deduplicate(results), nil
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
	if !s.sameOrigin(u) {
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

func (s *scanner) sameOrigin(u *url.URL) bool {
	return u != nil && strings.EqualFold(u.Scheme, s.origin.Scheme) &&
		strings.EqualFold(u.Host, s.origin.Host) && u.User == nil
}

func extractLinks(body string) []string {
	matches := hrefRE.FindAllStringSubmatch(body, 50)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

func extractGETForms(page *url.URL, body string) []*url.URL {
	var out []*url.URL
	for _, form := range formRE.FindAllStringSubmatch(body, 20) {
		attrs := attributes(form[1])
		if method := strings.ToUpper(attrs["method"]); method != "" && method != http.MethodGet {
			continue // POST/PUT forms are deliberately not submitted.
		}
		action := page
		if raw := attrs["action"]; raw != "" {
			action = resolve(page, raw)
		}
		if action == nil {
			continue
		}
		q := action.Query()
		for _, input := range inputRE.FindAllStringSubmatch(form[2], 50) {
			a := attributes(input[1])
			name := a["name"]
			if name == "" || strings.EqualFold(a["type"], "submit") || strings.EqualFold(a["type"], "button") {
				continue
			}
			if _, exists := q[name]; !exists {
				q.Set(name, a["value"])
			}
		}
		action.RawQuery = q.Encode()
		if len(q) > 0 {
			out = append(out, action)
		}
	}
	return out
}

func attributes(raw string) map[string]string {
	out := make(map[string]string)
	for _, m := range attrRE.FindAllStringSubmatch(raw, -1) {
		out[strings.ToLower(m[1])] = m[2]
	}
	return out
}

func resolve(base *url.URL, raw string) *url.URL {
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

func cloneURL(u *url.URL) *url.URL {
	v := *u
	return &v
}

func canonical(u *url.URL) string {
	v := cloneURL(u)
	v.Fragment = ""
	return v.String()
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
		ID: "sqli-" + kind + "-" + safeID(u.Host+u.Path+"-"+parameter),
		Title: title,
		Category: "sql-injection",
		Severity: severity,
		Status: "potential",
		Confidence: confidence,
		Description: description,
		Evidence: fmt.Sprintf("URL: %s\nParameter: %s\n%s", u.Redacted(), parameter, evidence),
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
