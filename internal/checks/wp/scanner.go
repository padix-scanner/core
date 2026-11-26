// Package wp performs lightweight WordPress detection and high-signal
// checks inspired by CMSeeK's WordPress deep-scan module.
//
// Only same-origin GET requests are issued. The check is bounded and
// intended for authorized assessments. All results are consolidated into a
// single finding.
package wp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"core/internal/httpx"
	"core/pkg/constants"
	"core/pkg/models"
)

const (
	maxBodyBytes   = 512 << 10
	defaultTimeout = 5 * time.Second
)

var (
	generatorRE         = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	wpContentRE         = regexp.MustCompile(`(?i)/wp-content/`)
	wpIncludesRE        = regexp.MustCompile(`(?i)/wp-includes/`)
	versionFromReadmeRE = regexp.MustCompile(`(?i)Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	versionFromCSSRE    = regexp.MustCompile(`(?i)Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	userJSONRE          = regexp.MustCompile(`"slug"\s*:\s*"([^"]+)"`)
	authorRedirectRE    = regexp.MustCompile(`(?i)/author/([^/\s"'<>]+)`)
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
	final  string // final URL after (same-origin) redirects
}

type scanner struct {
	cfg    Config
	origin *url.URL
	client *http.Client
}

// issue is one individual WordPress observation. Issues are folded into the
// single summary finding returned by Assess.
type issue struct {
	severity string
	title    string
	detail   string
}

var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Assess runs WordPress detection and a set of high-signal checks against
// the given target URL (scheme://host[:port]/). It returns at most one
// finding: nil when the site is not WordPress, otherwise a summary of every
// detection and issue.
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

	// Follow same-site redirects once up front and use the origin the site
	// really serves from. An unreachable target is an error, not "no findings".
	origin, err := httpx.ResolveOrigin(ctx, base, cfg.Timeout, cfg.UserAgent)
	if err != nil {
		return nil, err
	}

	s := &scanner{
		cfg:    cfg,
		origin: origin,
		client: httpx.NewClient(cfg.Timeout, func(next *url.URL) bool {
			return sameOrigin(next, origin)
		}),
	}
	defer s.client.CloseIdleConnections()

	// 1. Fetch home page and detect WordPress.
	home, err := s.get(ctx, s.origin)
	if err != nil {
		return nil, fmt.Errorf("fetch home page: %w", err)
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
		return nil, nil
	}

	var issues []issue

	// 2. Version detection.
	version, versionSource := detectVersion(home.body, s, ctx)

	// 3. User enumeration via REST API.
	if users := s.enumerateUsersREST(ctx); len(users) > 0 {
		issues = append(issues, issue{
			severity: "medium",
			title:    "User enumeration via REST API",
			detail:   "/wp-json/wp/v2/users is public; users: " + strings.Join(users, ", "),
		})
	}

	// 4. User enumeration via author parameter.
	if users := s.enumerateUsersAuthor(ctx); len(users) > 0 {
		issues = append(issues, issue{
			severity: "medium",
			title:    "User enumeration via author parameter",
			detail:   "?author=N leaks usernames: " + strings.Join(users, ", "),
		})
	}

	// 5. xmlrpc.php
	if s.probeXMLRPC(ctx) {
		issues = append(issues, issue{
			severity: "medium",
			title:    "xmlrpc.php is enabled",
			detail:   "may allow brute-force amplification or pingback abuse",
		})
	}

	// 6. Sensitive / information-disclosure files.
	for _, path := range []struct {
		p, title, sev, desc string
	}{
		{"/readme.html", "readme.html exposed", "low", "reveals the WordPress version"},
		{"/license.txt", "license.txt exposed", "info", "publicly accessible"},
		{"/wp-config.php.bak", "Possible wp-config.php backup", "high", "may contain database credentials"},
		{"/wp-config.php.old", "Possible wp-config.php backup", "high", "may contain database credentials"},
		{"/wp-config.php~", "Possible wp-config.php backup", "high", "may contain database credentials"},
		{"/.wp-config.php.swp", "Possible wp-config.php swap file", "high", "Vim swap file may be exposed"},
	} {
		if s.probePath(ctx, path.p) {
			issues = append(issues, issue{
				severity: path.sev,
				title:    path.title,
				detail:   path.p + " – " + path.desc,
			})
		}
	}

	// 7. User registration status (light check).
	if s.registrationOpen(ctx) {
		issues = append(issues, issue{
			severity: "low",
			title:    "User registration appears open",
			detail:   "/wp-login.php?action=register returned a registration form",
		})
	}

	return []models.Finding{
		summarize(s.origin, detectionEvidence, version, versionSource, issues),
	}, nil
}

// summarize folds the detection data and all issues into one finding.
// Severity is the highest severity among the issues; issues are listed from
// most to least severe.
func summarize(origin *url.URL, detection, version, versionSource string, issues []issue) models.Finding {
	sort.SliceStable(issues, func(i, j int) bool {
		return severityRank[issues[i].severity] > severityRank[issues[j].severity]
	})

	top := "info"
	actionable := 0
	for _, is := range issues {
		if severityRank[is.severity] > severityRank[top] {
			top = is.severity
		}
		if is.severity != "info" {
			actionable++
		}
	}

	status := "informational"
	if actionable > 0 {
		status = "exposed"
	}

	versionText := "version not identified"
	if version != "" {
		versionText = "version " + version
	}

	description := fmt.Sprintf("WordPress detected (%s).", versionText)
	switch {
	case actionable == 0:
		description += " No exposure issues were found."
	case actionable == 1:
		description += " 1 issue found."
	default:
		description += fmt.Sprintf(" %d issues found.", actionable)
	}
	if version != "" {
		description += " Compare the version against known vulnerabilities for this release."
	}

	var ev []string
	ev = append(ev, "Detection: "+detection)
	if version != "" {
		ev = append(ev, fmt.Sprintf("Version: %s (source: %s)", version, versionSource))
	}
	for _, is := range issues {
		ev = append(ev, fmt.Sprintf("[%s] %s: %s", strings.ToUpper(is.severity), is.title, is.detail))
	}

	return models.Finding{
		ID:          "wordpress-" + safeID(origin.Host),
		Title:       "WordPress assessment summary",
		Category:    "wordpress",
		Severity:    top,
		Status:      status,
		Confidence:  "medium",
		Description: description,
		Evidence:    strings.Join(ev, "\n"),
	}
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
		// The client follows ?author=N → /author/<slug>/ inside the origin, so
		// the final URL (and the archive page body) carries the slug.
		for _, candidate := range []string{resp.final, resp.body} {
			if m := authorRedirectRE.FindStringSubmatch(candidate); len(m) > 1 {
				slug := strings.TrimSpace(m[1])
				if slug == "" {
					continue
				}
				if _, ok := seen[slug]; !ok {
					seen[slug] = struct{}{}
					users = append(users, slug)
				}
				break
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
