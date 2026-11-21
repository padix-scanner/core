// Package wp performs lightweight WordPress detection and high-signal
// checks inspired by CMSeeK's WordPress deep-scan module.
//
// Only same-origin GET requests are issued. The check is bounded and
// intended for authorized assessments.
package wp

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
	defaultTimeout = 5 * time.Second
)

var (
	generatorRE = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	wpContentRE = regexp.MustCompile(`(?i)/wp-content/`)
	wpIncludesRE = regexp.MustCompile(`(?i)/wp-includes/`)
	versionFromReadmeRE = regexp.MustCompile(`(?i)Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	versionFromCSSRE = regexp.MustCompile(`(?i)Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	userJSONRE = regexp.MustCompile(`"slug"\s*:\s*"([^"]+)"`)
	authorRedirectRE = regexp.MustCompile(`(?i)/author/([^/\s"'<>]+)`)
)

// Config bounds request behaviour.
type Config struct {
	Timeout   time.Duration
	UserAgent string
}

func DefaultConfig() Config {
	return Config{
		Timeout:   defaultTimeout,
		UserAgent: constants.AppUserAgent,
	}
}

type response struct {
	status int
	body   string
	final  string // final URL after redirects (we disable auto-follow)
}

type scanner struct {
	cfg    Config
	origin *url.URL
	client *http.Client
}

// Assess runs WordPress detection and a set of high-signal checks against
// the given target URL (scheme://host[:port]/).
func Assess(ctx context.Context, target string, cfg Config) ([]models.Finding, error) {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" ||
		(base.Scheme != "http" && base.Scheme != "https") || base.User != nil {
		return nil, fmt.Errorf("invalid assessment URL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
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

	var findings []models.Finding

	// 1. Fetch home page and detect WordPress.
	home, err := s.get(ctx, base)
	if err != nil {
		return findings, nil
	}

	isWP, detectionEvidence := detectWordPress(home.body)
	if !isWP {
		// Still probe a couple of classic paths in case the front page is
		// heavily customised.
		if s.probePath(ctx, "/wp-login.php") || s.probePath(ctx, "/wp-admin/") {
			isWP = true
			detectionEvidence = "wp-login.php or wp-admin reachable"
		}
	}
	if !isWP {
		return findings, nil
	}

	findings = append(findings, models.Finding{
		ID:          "wp-detected",
		Title:       "WordPress detected",
		Category:    "wordpress",
		Severity:    "info",
		Status:      "informational",
		Confidence:  "high",
		Description: "The target appears to be running WordPress. Further WordPress-specific checks will be performed.",
		Evidence:    detectionEvidence,
	})

	// 2. Version detection.
	if ver, src := detectVersion(home.body, s, ctx); ver != "" {
		findings = append(findings, models.Finding{
			ID:          "wp-version-" + safeID(ver),
			Title:       "WordPress version identified",
			Category:    "wordpress",
			Severity:    "info",
			Status:      "informational",
			Confidence:  "medium",
			Description: "A WordPress version string was observed. Compare against known vulnerabilities for this release.",
			Evidence:    fmt.Sprintf("Version: %s\nSource: %s", ver, src),
		})
	}

	// 3. User enumeration via REST API.
	if users := s.enumerateUsersREST(ctx); len(users) > 0 {
		findings = append(findings, models.Finding{
			ID:          "wp-user-enum-rest",
			Title:       "WordPress user enumeration via REST API",
			Category:    "wordpress",
			Severity:    "medium",
			Status:      "exposed",
			Confidence:  "high",
			Description: "The /wp-json/wp/v2/users endpoint is publicly accessible and returns user information. Restrict it or require authentication.",
			Evidence:    "Users: " + strings.Join(users, ", "),
		})
	}

	// 4. User enumeration via author parameter.
	if users := s.enumerateUsersAuthor(ctx); len(users) > 0 {
		findings = append(findings, models.Finding{
			ID:          "wp-user-enum-author",
			Title:       "WordPress user enumeration via author parameter",
			Category:    "wordpress",
			Severity:    "medium",
			Status:      "exposed",
			Confidence:  "medium",
			Description: "Author archives or redirects leak usernames. Disable author archives or return generic responses.",
			Evidence:    "Users: " + strings.Join(users, ", "),
		})
	}

	// 5. xmlrpc.php
	if s.probeXMLRPC(ctx) {
		findings = append(findings, models.Finding{
			ID:          "wp-xmlrpc",
			Title:       "WordPress xmlrpc.php is enabled",
			Category:    "wordpress",
			Severity:    "medium",
			Status:      "exposed",
			Confidence:  "high",
			Description: "xmlrpc.php responds and may allow brute-force amplification or pingback abuse. Disable XML-RPC if not required.",
			Evidence:    "Path: /xmlrpc.php returned a recognizable WordPress XML-RPC response",
		})
	}

	// 6. Sensitive / information-disclosure files.
	for _, path := range []struct {
		p, title, sev, desc string
	}{
		{"/readme.html", "WordPress readme.html exposed", "low",
			"readme.html is publicly accessible and often reveals the WordPress version."},
		{"/license.txt", "WordPress license.txt exposed", "info",
			"license.txt is publicly accessible."},
		{"/wp-config.php.bak", "Possible wp-config.php backup", "high",
			"A backup of wp-config.php appears to be reachable. This file typically contains database credentials."},
		{"/wp-config.php.old", "Possible wp-config.php backup", "high",
			"A backup of wp-config.php appears to be reachable."},
		{"/wp-config.php~", "Possible wp-config.php backup", "high",
			"A backup of wp-config.php appears to be reachable."},
		{"/.wp-config.php.swp", "Possible wp-config.php swap file", "high",
			"A Vim swap file for wp-config.php may be exposed."},
	} {
		if s.probePath(ctx, path.p) {
			findings = append(findings, models.Finding{
				ID:          "wp-file-" + safeID(path.p),
				Title:       path.title,
				Category:    "wordpress",
				Severity:    path.sev,
				Status:      "exposed",
				Confidence:  "medium",
				Description: path.desc,
				Evidence:    "URL: " + s.origin.String() + strings.TrimPrefix(path.p, "/"),
			})
		}
	}

	// 7. User registration status (light check).
	if s.registrationOpen(ctx) {
		findings = append(findings, models.Finding{
			ID:          "wp-registration-open",
			Title:       "WordPress user registration appears open",
			Category:    "wordpress",
			Severity:    "low",
			Status:      "exposed",
			Confidence:  "medium",
			Description: "The registration form is reachable. Confirm whether public registration is intentional.",
			Evidence:    "Path: /wp-login.php?action=register returned a registration form",
		})
	}

	return findings, nil
}

func detectWordPress(body string) (bool, string) {
	lower := strings.ToLower(body)
	var reasons []string
	if wpContentRE.MatchString(lower) {
		reasons = append(reasons, "/wp-content/ present")
	}
	if wpIncludesRE.MatchString(lower) {
		reasons = append(reasons, "/wp-includes/ present")
	}
	if m := generatorRE.FindStringSubmatch(body); len(m) > 1 &&
		strings.Contains(strings.ToLower(m[1]), "wordpress") {
		reasons = append(reasons, "generator meta: "+strings.TrimSpace(m[1]))
	}
	if strings.Contains(lower, "wp-json") || strings.Contains(lower, "wp-emoji") {
		reasons = append(reasons, "WordPress-specific script/JSON markers")
	}
	if len(reasons) == 0 {
		return false, ""
	}
	return true, strings.Join(reasons, "; ")
}

func detectVersion(homeBody string, s *scanner, ctx context.Context) (string, string) {
	// Generator meta is the cleanest source.
	if m := generatorRE.FindStringSubmatch(homeBody); len(m) > 1 {
		content := strings.TrimSpace(m[1])
		if strings.Contains(strings.ToLower(content), "wordpress") {
			// e.g. "WordPress 6.4.2"
			parts := strings.Fields(content)
			for _, p := range parts {
				if matched, _ := regexp.MatchString(`^[0-9]+\.[0-9]`, p); matched {
					return p, "generator meta tag"
				}
			}
		}
	}

	// readme.html
	u := *s.origin
	u.Path = "/readme.html"
	u.RawQuery = ""
	resp, err := s.get(ctx, &u)
	if err == nil && resp.status == 200 {
		if m := versionFromReadmeRE.FindStringSubmatch(resp.body); len(m) > 1 {
			return m[1], "readme.html"
		}
	}

	// Default theme style.css (twentytwenty* / twenty*)
	for _, theme := range []string{
		"twentytwentyfour", "twentytwentythree", "twentytwentytwo",
		"twentytwentyone", "twentytwenty", "twentyseventeen",
	} {
		u.Path = "/wp-content/themes/" + theme + "/style.css"
		resp, err := s.get(ctx, &u)
		if err == nil && resp.status == 200 {
			if m := versionFromCSSRE.FindStringSubmatch(resp.body); len(m) > 1 {
				return m[1], "theme style.css (" + theme + ")"
			}
		}
	}
	return "", ""
}

func (s *scanner) enumerateUsersREST(ctx context.Context) []string {
	u := *s.origin
	u.Path = "/wp-json/wp/v2/users"
	u.RawQuery = ""
	resp, err := s.get(ctx, &u)
	if err != nil || resp.status != 200 {
		return nil
	}
	// Very light JSON scrape – look for "slug" fields.
	matches := userJSONRE.FindAllStringSubmatch(resp.body, 20)
	seen := make(map[string]struct{})
	var users []string
	for _, m := range matches {
		slug := strings.TrimSpace(m[1])
		if slug == "" {
			continue
		}
		if _, ok := seen[slug]; ok {
			continue
		}
		seen[slug] = struct{}{}
		users = append(users, slug)
	}
	return users
}

func (s *scanner) enumerateUsersAuthor(ctx context.Context) []string {
	var users []string
	seen := make(map[string]struct{})
	for id := 1; id <= 5; id++ {
		if err := ctx.Err(); err != nil {
			break
		}
		u := *s.origin
		u.Path = "/"
		u.RawQuery = fmt.Sprintf("author=%d", id)
		resp, err := s.get(ctx, &u)
		if err != nil {
			continue
		}
		// 301/302 to /author/slug/ or body contains /author/slug/
		if resp.status >= 300 && resp.status < 400 {
			// Location header is not available from our limited response;
			// fall through to body scan of the (possible) error page.
		}
		if m := authorRedirectRE.FindStringSubmatch(resp.body); len(m) > 1 {
			slug := strings.TrimSpace(m[1])
			if slug != "" {
				if _, ok := seen[slug]; !ok {
					seen[slug] = struct{}{}
					users = append(users, slug)
				}
			}
		}
	}
	return users
}

func (s *scanner) probeXMLRPC(ctx context.Context) bool {
	u := *s.origin
	u.Path = "/xmlrpc.php"
	u.RawQuery = ""
	resp, err := s.get(ctx, &u)
	if err != nil {
		return false
	}
	// Classic response is 405 with body containing "XML-RPC server accepts POST requests only"
	// or 200 with a method list when GET is allowed.
	lower := strings.ToLower(resp.body)
	return strings.Contains(lower, "xml-rpc") ||
		strings.Contains(lower, "xmlrpc") ||
		(resp.status == 405 && strings.Contains(lower, "post"))
}

func (s *scanner) registrationOpen(ctx context.Context) bool {
	u := *s.origin
	u.Path = "/wp-login.php"
	u.RawQuery = "action=register"
	resp, err := s.get(ctx, &u)
	if err != nil || resp.status != 200 {
		return false
	}
	lower := strings.ToLower(resp.body)
	return strings.Contains(lower, "register") &&
		(strings.Contains(lower, "user_login") || strings.Contains(lower, "user_email"))
}

func (s *scanner) probePath(ctx context.Context, path string) bool {
	u := *s.origin
	u.Path = path
	u.RawQuery = ""
	resp, err := s.get(ctx, &u)
	if err != nil {
		return false
	}
	return resp.status == 200 && len(resp.body) > 50
}

func (s *scanner) get(ctx context.Context, u *url.URL) (response, error) {
	if !sameOrigin(u, s.origin) {
		return response{}, fmt.Errorf("cross-origin request blocked")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	resp, err := s.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return response{
		status: resp.StatusCode,
		body:   string(body),
		final:  resp.Request.URL.String(),
	}, err
}

func sameOrigin(u, origin *url.URL) bool {
	return u != nil && strings.EqualFold(u.Scheme, origin.Scheme) &&
		strings.EqualFold(u.Host, origin.Host) && u.User == nil
}

func safeID(v string) string {
	v = strings.ToLower(v)
	var b strings.Builder
	lastDash := false
	for _, r := range v {
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
