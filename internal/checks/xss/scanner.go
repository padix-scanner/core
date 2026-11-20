package xss

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"core/internal/checks/crawl"
	"core/pkg/constants"
	"core/pkg/models"
)

const (
	maxBodyBytes = 512 << 10
	maxPages     = 20
	maxParams    = 8
)

var payloads = []string{
	"<script>alert(1)</script>",
	"\"<svg onload=alert(1)>",
	"<img src=x onerror=alert(1)>",
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

// Assess crawls same-origin HTTP pages and tests each query parameter for
// reflected cross-site scripting by injecting payloads and checking whether
// they appear verbatim in the response body.
func Assess(ctx context.Context, target string, cfg Config) ([]models.Finding, error) {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("invalid assessment URL")
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

	s := &scanner{
		cfg:    cfg,
		origin: base,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: cfg.Timeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	defer s.client.CloseIdleConnections()

	var results []models.Finding
	err = crawl.Crawl(ctx, base, cfg.MaxPages, s.fetch, func(u *url.URL, body string) error {
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

func (s *scanner) fetch(ctx context.Context, u *url.URL) (string, error) {
	resp, err := s.get(ctx, u)
	if err != nil {
		return "", err
	}
	if resp.status < 200 || resp.status >= 400 {
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
		for _, payload := range payloads {
			if err := ctx.Err(); err != nil {
				break
			}
			testURL := cloneURL(target)
			q := testURL.Query()
			q.Set(key, payload)
			testURL.RawQuery = q.Encode()
			resp, err := s.get(ctx, testURL)
			if err != nil {
				continue
			}
			if strings.Contains(resp.body, payload) {
				out = append(out, finding("reflected", testURL, key,
					"Reflected cross-site scripting",
					"medium", "low",
					"The payload was reflected verbatim in the response body, indicating a potential XSS. Manual verification is required.",
					fmt.Sprintf("URL: %s\nParameter: %s\nPayload: %s", testURL.Redacted(), key, payload)))
				break
			}
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

func finding(kind string, u *url.URL, parameter, title, severity, confidence, description, evidence string) models.Finding {
	return models.Finding{
		ID:          "xss-" + kind + "-" + safeID(u.Host+u.Path+"-"+parameter),
		Title:       title,
		Category:    "xss",
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
