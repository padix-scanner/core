// Package dorks generates categorized Google (and multi-engine) dork queries
// for a target domain, based on the well-known dorks_hunter set.
//
// Findings are informational / low severity and intended as OSINT guidance.
// The scanner does not scrape search engines; it only produces the queries
// and ready-to-use search URLs so the operator can run them manually or with
// an external tool such as xnldorker.
package dorks

import (
	"fmt"
	"net/url"
	"strings"

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
}

var templates = []dorkTemplate{
	{
		Category: ".git folders",
		Query:    `inurl:"/.git" {{domain}} -github`,
	},
	{
		Category: "Backup files",
		Query:    `site:{{domain}} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup`,
	},
	{
		Category: "Exposed documents",
		Query:    `site:{{domain}} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv | filetype:doc | filetype:docx | filetype:xls | filetype:xlsx | filetype:ppt | filetype:pptx | filetype:mdb | filetype:pdf | filetype:sql | filetype:txt | filetype:rtf | filetype:csv | filetype:xml | filetype:conf | filetype:dat | filetype:ini | filetype:log | index of:id_rsa id_rsa.pub | filetype:py | filetype:html | filetype:sh | filetype:odt | filetype:key | filetype:sign | filetype:md | filetype:old | filetype:bin | filetype:cer | filetype:crt | filetype:pfx | filetype:crl | filetype:crs | filetype:der`,
	},
	{
		Category: "Confidential documents",
		Query:    `inurl:{{target}} not for distribution | confidential | "employee only" | proprietary | top secret | classified | trade secret | internal | private filetype:xls OR filetype:csv OR filetype:doc OR filetype:pdf`,
	},
	{
		Category: "Config files",
		Query:    `site:{{domain}} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini`,
	},
	{
		Category: "Database files",
		Query:    `site:{{domain}} ext:sql | ext:dbf | ext:mdb`,
	},
	{
		Category: "Other sensitive files / index pages",
		Query:    `site:{{domain}} intitle:index.of | ext:log | ext:php intitle:phpinfo "published by the PHP Group" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:"/phpinfo.php" | inurl:".htaccess" | ext:swf`,
	},
	{
		Category: "SQL errors",
		Query:    `site:{{domain}} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"`,
	},
	{
		Category: "PHP errors",
		Query:    `site:{{domain}} "PHP Parse error" | "PHP Warning" | "PHP Error"`,
	},
	{
		Category: "WordPress files",
		Query:    `site:{{domain}} inurl:wp-content | inurl:wp-includes`,
	},
	{
		Category: "Project management sites",
		Query:    `site:trello.com | site:*.atlassian.net "{{target}}"`,
	},
	{
		Category: "Subdomains",
		Query:    `site:*.{{domain}}`,
	},
	{
		Category: "Sub-subdomains",
		Query:    `site:*.*.{{domain}}`,
	},
	{
		Category: "Path traversal / directory listings",
		Query:    `"{{target}}" intitle:"index of" "parent directory" | intitle:"index of" "DCIM" | intitle:"index of" "ftp" | intitle:"index of" "backup" | intitle:"index of" "mail" | intitle:"index of" "password" | intitle:"index of" "pub" | intitle:"index of" ".git"`,
	},
	{
		Category: "GitLab / GitHub / Bitbucket",
		Query:    `site:github.com | site:gitlab.com | site:bitbucket.org "{{target}}"`,
	},
	{
		Category: "Cloud buckets (S3 / GCP)",
		Query:    `site:.s3.amazonaws.com | site:storage.googleapis.com | site:amazonaws.com "{{target}}"`,
	},
	{
		Category: "Traefik dashboard",
		Query:    `intitle:traefik inurl:8080/dashboard "{{target}}"`,
	},
	{
		Category: "Jenkins",
		Query:    `intitle:"Dashboard [Jenkins]" "{{target}}"`,
	},
	{
		Category: "Login pages",
		Query:    `site:{{domain}} inurl:signup | inurl:register | intitle:Signup | inurl:admin | inurl:login | inurl:adminlogin | inurl:cplogin | inurl:weblogin | inurl:quicklogin | inurl:wp-admin | inurl:wp-login | inurl:portal | inurl:userportal | inurl:loginpanel | inurl:memberlogin | inurl:remote | inurl:dashboard | inurl:auth | inurl:exchange | inurl:ForgotPassword | inurl:test`,
	},
	{
		Category: "Open redirects",
		Query:    `site:{{domain}} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http`,
	},
	{
		Category: "Code share sites",
		Query:    `site:sharecode.io | site:controlc.com | site:codepad.co | site:ideone.com | site:codebeautify.org | site:jsdelivr.com | site:codeshare.io | site:codepen.io | site:repl.it | site:jsfiddle.net "{{target}}"`,
	},
	{
		Category: "Other 3rd-party sites",
		Query:    `site:gitter.im | site:papaly.com | site:productforums.google.com | site:coggle.it | site:replt.it | site:ycombinator.com | site:libraries.io | site:npm.runkit.com | site:npmjs.com | site:scribd.com "{{target}}"`,
	},
	{
		Category: "Stack Overflow",
		Query:    `site:stackoverflow.com "{{domain}}"`,
	},
	{
		Category: "Pastebin-like sites",
		Query:    `site:justpaste.it | site:heypasteit.com | site:pastebin.com "{{target}}"`,
	},
	{
		Category: "Apache Struts RCE indicators",
		Query:    `site:{{domain}} ext:action | ext:struts | ext:do`,
	},
	{
		Category: "LinkedIn employees",
		Query:    `site:linkedin.com employees {{domain}}`,
	},
}

// Assess produces one informational finding per dork category for the given
// target hostname. The endpoint argument is ignored; only the host part of
// the supplied target is used.
func Assess(target string) []models.Finding {
	domain, sld := extractDomainParts(target)
	if domain == "" {
		return nil
	}

	findings := make([]models.Finding, 0, len(templates))
	for _, t := range templates {
		query := strings.ReplaceAll(t.Query, "{{domain}}", domain)
		query = strings.ReplaceAll(query, "{{target}}", sld)

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
	return findings
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
