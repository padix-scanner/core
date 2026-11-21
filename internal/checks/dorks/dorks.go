// Package dorks generates categorized Google (and multi-engine) dork queries
// for a target domain, based on the well-known dorks_hunter set, and optionally
// requests results from search engines (inspired by xnldorker).
//
// Generation findings are informational. When requesting is enabled, a bounded
// subset of high-signal dorks is submitted to DuckDuckGo Lite (HTML, no JS)
// and discovered same-domain URLs are reported as additional findings.
// The scanner does not solve captchas and deliberately limits request volume.
package dorks

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

// dorkTemplate holds a human-readable category and the query template.
// Placeholders:
//
//	{{domain}}  – full hostname / domain as supplied (e.g. example.com)
//	{{target}}  – registered-domain label only (e.g. example)
type dorkTemplate struct {
	Category string
	Query    string
	// Request marks templates that are safe/high-signal enough to actively
	// query via DuckDuckGo Lite when requesting is enabled.
	Request bool
}

var templates = []dorkTemplate{
	{
		Category: ".git folders",
		Query:    `inurl:"/.git" {{domain}} -github`,
		Request:  true,
	},
	{
		Category: "Backup files",
		Query:    `site:{{domain}} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup`,
		Request:  true,
	},
	{
		Category: "Exposed documents",
		Query:    `site:{{domain}} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv | filetype:doc | filetype:docx | filetype:xls | filetype:xlsx | filetype:ppt | filetype:pptx | filetype:mdb | filetype:pdf | filetype:sql | filetype:txt | filetype:rtf | filetype:csv | filetype:xml | filetype:conf | filetype:dat | filetype:ini | filetype:log | index of:id_rsa id_rsa.pub | filetype:py | filetype:html | filetype:sh | filetype:odt | filetype:key | filetype:sign | filetype:md | filetype:old | filetype:bin | filetype:cer | filetype:crt | filetype:pfx | filetype:crl | filetype:crs | filetype:der`,
		Request:  false,
	},
	{
		Category: "Confidential documents",
		Query:    `inurl:{{target}} not for distribution | confidential | "employee only" | proprietary | top secret | classified | trade secret | internal | private filetype:xls OR filetype:csv OR filetype:doc OR filetype:pdf`,
		Request:  false,
	},
	{
		Category: "Config files",
		Query:    `site:{{domain}} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini`,
		Request:  true,
	},
	{
		Category: "Database files",
		Query:    `site:{{domain}} ext:sql | ext:dbf | ext:mdb`,
		Request:  true,
	},
	{
		Category: "Other sensitive files / index pages",
		Query:    `site:{{domain}} intitle:index.of | ext:log | ext:php intitle:phpinfo "published by the PHP Group" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:"/phpinfo.php" | inurl:".htaccess" | ext:swf`,
		Request:  true,
	},
	{
		Category: "SQL errors",
		Query:    `site:{{domain}} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"`,
		Request:  true,
	},
	{
		Category: "PHP errors",
		Query:    `site:{{domain}} "PHP Parse error" | "PHP Warning" | "PHP Error"`,
		Request:  true,
	},
	{
		Category: "WordPress files",
		Query:    `site:{{domain}} inurl:wp-content | inurl:wp-includes`,
		Request:  true,
	},
	{
		Category: "Project management sites",
		Query:    `site:trello.com | site:*.atlassian.net "{{target}}"`,
		Request:  false,
	},
	{
		Category: "Subdomains",
		Query:    `site:*.{{domain}}`,
		Request:  false,
	},
	{
		Category: "Sub-subdomains",
		Query:    `site:*.*.{{domain}}`,
		Request:  false,
	},
	{
		Category: "Path traversal / directory listings",
		Query:    `"{{target}}" intitle:"index of" "parent directory" | intitle:"index of" "DCIM" | intitle:"index of" "ftp" | intitle:"index of" "backup" | intitle:"index of" "mail" | intitle:"index of" "password" | intitle:"index of" "pub" | intitle:"index of" ".git"`,
		Request:  true,
	},
	{
		Category: "GitLab / GitHub / Bitbucket",
		Query:    `site:github.com | site:gitlab.com | site:bitbucket.org "{{target}}"`,
		Request:  false,
	},
	{
		Category: "Cloud buckets (S3 / GCP)",
		Query:    `site:.s3.amazonaws.com | site:storage.googleapis.com | site:amazonaws.com "{{target}}"`,
		Request:  true,
	},
	{
		Category: "Traefik dashboard",
		Query:    `intitle:traefik inurl:8080/dashboard "{{target}}"`,
		Request:  false,
	},
	{
		Category: "Jenkins",
		Query:    `intitle:"Dashboard [Jenkins]" "{{target}}"`,
		Request:  false,
	},
	{
		Category: "Login pages",
		Query:    `site:{{domain}} inurl:signup | inurl:register | intitle:Signup | inurl:admin | inurl:login | inurl:adminlogin | inurl:cplogin | inurl:weblogin | inurl:quicklogin | inurl:wp-admin | inurl:wp-login | inurl:portal | inurl:userportal | inurl:loginpanel | inurl:memberlogin | inurl:remote | inurl:dashboard | inurl:auth | inurl:exchange | inurl:ForgotPassword | inurl:test`,
		Request:  false,
	},
	{
		Category: "Open redirects",
		Query:    `site:{{domain}} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http`,
		Request:  false,
	},
	{
		Category: "Code share sites",
		Query:    `site:sharecode.io | site:controlc.com | site:codepad.co | site:ideone.com | site:codebeautify.org | site:jsdelivr.com | site:codeshare.io | site:codepen.io | site:repl.it | site:jsfiddle.net "{{target}}"`,
		Request:  false,
	},
	{
		Category: "Other 3rd-party sites",
		Query:    `site:gitter.im | site:papaly.com | site:productforums.google.com | site:coggle.it | site:replt.it | site:ycombinator.com | site:libraries.io | site:npm.runkit.com | site:npmjs.com | site:scribd.com "{{target}}"`,
		Request:  false,
	},
	{
		Category: "Stack Overflow",
		Query:    `site:stackoverflow.com "{{domain}}"`,
		Request:  false,
	},
	{
		Category: "Pastebin-like sites",
		Query:    `site:justpaste.it | site:heypasteit.com | site:pastebin.com "{{target}}"`,
		Request:  true,
	},
	{
		Category: "Apache Struts RCE indicators",
		Query:    `site:{{domain}} ext:action | ext:struts | ext:do`,
		Request:  false,
	},
	{
		Category: "LinkedIn employees",
		Query:    `site:linkedin.com employees {{domain}}`,
		Request:  false,
	},
}

// Config controls generation and the optional active requester.
type Config struct {
	// Request enables live queries against DuckDuckGo Lite for marked templates.
	Request bool
	// MaxRequests caps how many dork queries are actually sent.
	MaxRequests int
	// Timeout per HTTP request.
	Timeout time.Duration
	// UserAgent for outbound requests.
	UserAgent string
	// MaxResultsPerDork limits links kept from a single search response.
	MaxResultsPerDork int
}

// DefaultConfig returns a conservative configuration suitable for automated scans.
func DefaultConfig() Config {
	return Config{
		Request:           true,
		MaxRequests:       8,
		Timeout:           8 * time.Second,
		UserAgent:         constants.AppUserAgent,
		MaxResultsPerDork: 15,
	}
}

// Assess produces informational dork findings for the target hostname.
// When cfg.Request is true, a bounded subset of high-signal dorks is also
// submitted to DuckDuckGo Lite and any same-domain (or explicitly targeted
// third-party) result URLs are reported.
func Assess(ctx context.Context, target string, cfg Config) []models.Finding {
	domain, sld := extractDomainParts(target)
	if domain == "" {
		return nil
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 8
	}
	if cfg.MaxResultsPerDork <= 0 {
		cfg.MaxResultsPerDork = 15
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = constants.AppUserAgent
	}

	findings := make([]models.Finding, 0, len(templates)+cfg.MaxRequests)

	// 1. Always emit the static dork guidance findings (xnldorker-style query set).
	for _, t := range templates {
		query := expandQuery(t.Query, domain, sld)
		googleURL := "https://www.google.com/search?q=" + url.QueryEscape(query)

		findings = append(findings, models.Finding{
			ID:          "dork-" + slug(t.Category),
			Title:       "Google dork: " + t.Category,
			Category:    "dorks",
			Severity:    "info",
			Status:      "informational",
			Confidence:  "high",
			Description: "Recommended OSINT search query. Run it manually in a search engine or with a tool such as xnldorker. Review results carefully; many hits are false positives.",
			Evidence: fmt.Sprintf(
				"Category: %s\nQuery: %s\nGoogle: %s",
				t.Category, query, googleURL,
			),
		})
	}

	// 2. Optional live requester (DuckDuckGo Lite), inspired by xnldorker.
	if cfg.Request {
		requested := 0
		client := &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: cfg.Timeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		defer client.CloseIdleConnections()

		for _, t := range templates {
			if !t.Request {
				continue
			}
			if requested >= cfg.MaxRequests {
				break
			}
			if err := ctx.Err(); err != nil {
				break
			}

			query := expandQuery(t.Query, domain, sld)
			links, err := requestDuckDuckGoLite(ctx, client, query, cfg)
			requested++
			if err != nil || len(links) == 0 {
				continue
			}

			// Keep only links that appear related to the target (same eTLD+1
			// or explicit third-party host already present in the query).
			relevant := filterRelevant(links, domain, sld)
			if len(relevant) == 0 {
				continue
			}
			if len(relevant) > cfg.MaxResultsPerDork {
				relevant = relevant[:cfg.MaxResultsPerDork]
			}

			findings = append(findings, models.Finding{
				ID:       "dork-results-" + slug(t.Category),
				Title:    "Dork results: " + t.Category,
				Category: "dorks",
				Severity: "info",
				Status:   "informational",
				Confidence: "medium",
				Description: "Live search results obtained via DuckDuckGo Lite for a high-signal dork. " +
					"Results are unauthenticated OSINT only; verify manually. " +
					"Inspired by xnldorker (https://github.com/xnl-h4ck3r/xnldorker).",
				Evidence: fmt.Sprintf(
					"Category: %s\nQuery: %s\nEngine: DuckDuckGo Lite\nResults (%d):\n%s",
					t.Category, query, len(relevant), strings.Join(relevant, "\n"),
				),
			})
		}
	}

	return findings
}

func expandQuery(tmpl, domain, sld string) string {
	q := strings.ReplaceAll(tmpl, "{{domain}}", domain)
	return strings.ReplaceAll(q, "{{target}}", sld)
}

// requestDuckDuckGoLite performs a single HTML search against DuckDuckGo Lite
// and returns candidate result URLs. No pagination is performed to stay
// within scan bounds and reduce captcha risk.
func requestDuckDuckGoLite(ctx context.Context, client *http.Client, dork string, cfg Config) ([]string, error) {
	searchURL := "https://lite.duckduckgo.com/lite/?q=" + url.QueryEscape(dork)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return nil, err
	}

	return parseDuckDuckGoLite(string(body)), nil
}

// href patterns used by DuckDuckGo Lite result pages.
var (
	ddgHrefRE = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>`)
	// //duckduckgo.com/l/?uddg=<urlencoded>
	ddgRedirectRE = regexp.MustCompile(`(?i)^//duckduckgo\.com/l/\?uddg=`)
)

func parseDuckDuckGoLite(body string) []string {
	matches := ddgHrefRE.FindAllStringSubmatch(body, 80)
	seen := make(map[string]struct{})
	var out []string

	for _, m := range matches {
		href := strings.TrimSpace(m[1])
		if href == "" {
			continue
		}

		// Unwrap DuckDuckGo redirect wrappers (same logic as xnldorker).
		if ddgRedirectRE.MatchString(href) {
			if u, err := url.Parse("https:" + href); err == nil {
				if q := u.Query().Get("uddg"); q != "" {
					if decoded, err := url.QueryUnescape(q); err == nil {
						href = decoded
					}
				}
			}
		}

		if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
			continue
		}

		// Drop DuckDuckGo / search-engine self links.
		lower := strings.ToLower(href)
		if strings.Contains(lower, "duckduckgo.") ||
			strings.Contains(lower, "duck.com") ||
			strings.Contains(lower, "bing.com") ||
			strings.Contains(lower, "google.") {
			continue
		}

		// Normalise fragment away.
		if u, err := url.Parse(href); err == nil {
			u.Fragment = ""
			href = u.String()
		}

		if _, ok := seen[href]; ok {
			continue
		}
		seen[href] = struct{}{}
		out = append(out, href)
	}
	return out
}

// filterRelevant keeps links that belong to the target domain / its
// subdomains, or that clearly match third-party hosts already present in
// the dork (github, s3, pastebin, etc.).
func filterRelevant(links []string, domain, sld string) []string {
	domain = strings.ToLower(domain)
	sld = strings.ToLower(sld)
	var out []string

	for _, link := range links {
		u, err := url.Parse(link)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Host)
		// Strip port if present.
		if h, _, err := netSplitHostPort(host); err == nil {
			host = h
		}

		if host == domain || strings.HasSuffix(host, "."+domain) {
			out = append(out, link)
			continue
		}
		// Allow common third-party hosts that dorks intentionally target.
		if strings.Contains(host, "github.com") ||
			strings.Contains(host, "gitlab.com") ||
			strings.Contains(host, "bitbucket.org") ||
			strings.Contains(host, "s3.amazonaws.com") ||
			strings.Contains(host, "storage.googleapis.com") ||
			strings.Contains(host, "pastebin.com") ||
			strings.Contains(host, "justpaste.it") ||
			strings.Contains(host, "trello.com") ||
			strings.Contains(host, "atlassian.net") {
			// Prefer links that also mention the target label in path/query.
			if sld != "" && (strings.Contains(strings.ToLower(link), sld) ||
				strings.Contains(host, sld)) {
				out = append(out, link)
			}
		}
	}
	return out
}

func netSplitHostPort(hostport string) (host, port string, err error) {
	if i := strings.LastIndex(hostport, ":"); i != -1 {
		return hostport[:i], hostport[i+1:], nil
	}
	return hostport, "", nil
}

// extractDomainParts returns (fullDomain, secondLevelDomain).
// fullDomain is the hostname without scheme/port/path.
// secondLevelDomain is a best-effort extraction of the registered-domain
// label (e.g. "example" from "www.example.com" or "example.co.uk").
func extractDomainParts(raw string) (domain, sld string) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")

	// Strip path / query / fragment if present.
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}
	// Strip port.
	if host, _, err := splitHostPort(raw); err == nil {
		raw = host
	}

	raw = strings.Trim(raw, ".")
	if raw == "" {
		return "", ""
	}

	domain = strings.ToLower(raw)
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return domain, domain
	}

	// Simple heuristic for the "target" label used by dorks_hunter.
	// Prefer the second-to-last label when there are at least two labels.
	// For multi-part TLDs (co.uk, com.au …) this is imperfect but good enough
	// for the majority of real-world targets and matches the spirit of the
	// original Python tool.
	if len(labels) >= 2 {
		sld = labels[len(labels)-2]
	} else {
		sld = labels[0]
	}
	return domain, sld
}

func splitHostPort(hostport string) (host, port string, err error) {
	// Minimal replacement for net.SplitHostPort that tolerates missing port.
	if i := strings.LastIndex(hostport, ":"); i != -1 {
		// IPv6 in brackets is not expected here (targets are hostnames/IPs
		// already normalized by the CLI).
		return hostport[:i], hostport[i+1:], nil
	}
	return hostport, "", nil
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
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
