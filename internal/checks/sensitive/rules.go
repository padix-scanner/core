package sensitive

import (
	"fmt"
	"regexp"
	"strings"
)

// validator inspects a response and, when the body really looks like the
// sensitive file, returns a short description of what matched. It must never
// return file contents (they can be secrets).
type validator func(r response) (marker string, ok bool)

type rule struct {
	Path        string
	Title       string
	Severity    string
	Confidence  string // defaults to "high"
	Description string
	Validate    validator
}

var (
	envLineRE    = regexp.MustCompile(`(?m)^(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=`)
	gitHeadRE    = regexp.MustCompile(`^(?:ref:\s*refs/\S+|[0-9a-f]{40})$`)
	htpasswdRE   = regexp.MustCompile(`(?m)^[^:\s<>]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}$)`)
	dockerFromRE = regexp.MustCompile(`(?m)^FROM\s+\S+`)
	laravelLogRE = regexp.MustCompile(`\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \w+\.(?:ERROR|WARNING|INFO|DEBUG|CRITICAL)`)
	phpErrorRE   = regexp.MustCompile(`PHP (?:Warning|Fatal error|Notice|Parse error|Deprecated):`)
)

/* ------------------------------------------------------------------ */
/* Validator helpers                                                   */
/* ------------------------------------------------------------------ */

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// isHTML reports whether the body looks like an HTML page. Plain-text
// validators reject HTML so that custom error pages and SPA shells are not
// mistaken for configuration files.
func isHTML(body string) bool {
	head := strings.ToLower(strings.TrimSpace(firstN(body, 512)))
	return strings.HasPrefix(head, "<!doctype html") ||
		strings.HasPrefix(head, "<html") ||
		strings.Contains(head, "<head") ||
		strings.Contains(head, "<body")
}

// prefix matches binary magic bytes.
func prefix(magic, desc string) validator {
	return func(r response) (string, bool) {
		if strings.HasPrefix(r.body, magic) {
			return desc, true
		}
		return "", false
	}
}

// textAll requires a non-HTML body containing every substring.
func textAll(desc string, subs ...string) validator {
	return func(r response) (string, bool) {
		if isHTML(r.body) {
			return "", false
		}
		for _, s := range subs {
			if !strings.Contains(r.body, s) {
				return "", false
			}
		}
		return desc, true
	}
}

// textAny requires a non-HTML body containing at least one substring.
func textAny(desc string, subs ...string) validator {
	return func(r response) (string, bool) {
		if isHTML(r.body) {
			return "", false
		}
		for _, s := range subs {
			if strings.Contains(r.body, s) {
				return desc, true
			}
		}
		return "", false
	}
}

// htmlAll is for pages that are legitimately HTML (phpinfo, status pages).
func htmlAll(desc string, subs ...string) validator {
	return func(r response) (string, bool) {
		for _, s := range subs {
			if !strings.Contains(r.body, s) {
				return "", false
			}
		}
		return desc, true
	}
}

func textRegexp(desc string, re *regexp.Regexp) validator {
	return func(r response) (string, bool) {
		if isHTML(r.body) || !re.MatchString(r.body) {
			return "", false
		}
		return desc, true
	}
}

/* ------------------------------------------------------------------ */
/* Specific validators                                                 */
/* ------------------------------------------------------------------ */

func gitHead(r response) (string, bool) {
	if isHTML(r.body) || !gitHeadRE.MatchString(strings.TrimSpace(r.body)) {
		return "", false
	}
	return "valid .git/HEAD reference", true
}

// envFile reports the number of assignments and up to five variable NAMES.
// Values are never recorded.
func envFile(r response) (string, bool) {
	if isHTML(r.body) {
		return "", false
	}
	m := envLineRE.FindAllStringSubmatch(r.body, -1)
	if len(m) < 2 {
		return "", false
	}
	keys := make([]string, 0, 5)
	for _, x := range m {
		if len(keys) == 5 {
			break
		}
		keys = append(keys, x[1])
	}
	return fmt.Sprintf("%d KEY=VALUE assignments (keys: %s)", len(m), strings.Join(keys, ", ")), true
}

func privateKey(r response) (string, bool) {
	if strings.Contains(r.body, "-----BEGIN") && strings.Contains(r.body, "PRIVATE KEY-----") {
		return "PEM private key header", true
	}
	return "", false
}

func sqlDump(r response) (string, bool) {
	return textAny("SQL dump statements",
		"CREATE TABLE", "INSERT INTO", "DROP TABLE IF EXISTS",
		"-- MySQL dump", "-- PostgreSQL database dump")(r)
}

func phpSource(r response) (string, bool) {
	if strings.Contains(r.body, "<?php") {
		return "raw PHP source returned instead of being executed", true
	}
	return "", false
}

func jsonWith(desc string, subs ...string) validator {
	return func(r response) (string, bool) {
		body := strings.TrimSpace(r.body)
		if !strings.HasPrefix(body, "{") {
			return "", false
		}
		for _, s := range subs {
			if !strings.Contains(body, s) {
				return "", false
			}
		}
		return desc, true
	}
}

/* ------------------------------------------------------------------ */
/* Rule table                                                          */
/* ------------------------------------------------------------------ */

var rules = []rule{
	// Secrets and credentials.
	{Path: "/.env", Title: "Environment file exposed", Severity: "critical",
		Description: "A .env file is publicly readable. These files normally contain database passwords, API keys and application secrets. Block access in the web server and rotate every secret it contained.",
		Validate:    envFile},
	{Path: "/.env.local", Title: "Environment file exposed", Severity: "critical",
		Description: "A .env.local file is publicly readable and may contain secrets. Block access and rotate the credentials.",
		Validate:    envFile},
	{Path: "/.env.production", Title: "Environment file exposed", Severity: "critical",
		Description: "A production environment file is publicly readable and may contain secrets. Block access and rotate the credentials.",
		Validate:    envFile},
	{Path: "/.env.backup", Title: "Environment file backup exposed", Severity: "critical",
		Description: "A backup of the environment file is publicly readable. Remove it and rotate the credentials.",
		Validate:    envFile},
	{Path: "/id_rsa", Title: "SSH private key exposed", Severity: "critical",
		Description: "A private key is publicly downloadable. Remove it immediately and replace the key pair everywhere it was authorised.",
		Validate:    privateKey},
	{Path: "/.ssh/id_rsa", Title: "SSH private key exposed", Severity: "critical",
		Description: "A private key is publicly downloadable. Remove it immediately and replace the key pair everywhere it was authorised.",
		Validate:    privateKey},
	{Path: "/.aws/credentials", Title: "AWS credentials file exposed", Severity: "critical",
		Description: "An AWS credentials file is publicly readable. Revoke and rotate the access keys immediately.",
		Validate:    textAll("AWS credentials file markers", "aws_access_key_id")},
	{Path: "/.npmrc", Title: "npm configuration with auth token exposed", Severity: "high",
		Description: "An .npmrc file containing registry credentials is publicly readable. Remove it and revoke the token.",
		Validate:    textAny("npm auth token entry", "_authToken", "_auth=")},
	{Path: "/.htpasswd", Title: "htpasswd file exposed", Severity: "high",
		Description: "The HTTP basic-auth password file is readable. Password hashes can be cracked offline. Move it outside the web root.",
		Validate:    textRegexp("htpasswd user:hash entries", htpasswdRE)},

	// Version control metadata.
	{Path: "/.git/HEAD", Title: "Git repository exposed", Severity: "high",
		Description: "The .git directory is publicly accessible. Attackers can reconstruct the full source code and history, which often contains secrets. Deny access to dot-directories.",
		Validate:    gitHead},
	{Path: "/.git/config", Title: "Git configuration exposed", Severity: "high",
		Description: "The .git/config file is publicly readable and may reveal remote URLs, including embedded credentials.",
		Validate:    textAll("git config [core] section", "[core]")},
	{Path: "/.svn/wc.db", Title: "Subversion working copy database exposed", Severity: "high",
		Description: "The .svn metadata is publicly accessible and reveals file paths and source code. Deny access to .svn.",
		Validate:    prefix("SQLite format 3\x00", "SQLite database header (.svn/wc.db)")},
	{Path: "/.DS_Store", Title: ".DS_Store file exposed", Severity: "low",
		Description: "A macOS .DS_Store file reveals directory contents and file names that are not otherwise linked.",
		Validate:    prefix("\x00\x00\x00\x01Bud1", "DS_Store header")},
	{Path: "/.idea/workspace.xml", Title: "IDE project metadata exposed", Severity: "low",
		Description: "JetBrains IDE project files are publicly readable and leak internal paths and project structure.",
		Validate:    textAll("JetBrains workspace XML", "<project", "<component name=")},

	// Backups and database dumps.
	{Path: "/backup.zip", Title: "Backup archive exposed", Severity: "high",
		Description: "A backup archive is publicly downloadable and may contain source code, configuration and data.",
		Validate:    prefix("PK\x03\x04", "ZIP archive header")},
	{Path: "/site.zip", Title: "Site archive exposed", Severity: "high",
		Description: "A site archive is publicly downloadable and may contain source code and configuration.",
		Validate:    prefix("PK\x03\x04", "ZIP archive header")},
	{Path: "/www.zip", Title: "Site archive exposed", Severity: "high",
		Description: "A site archive is publicly downloadable and may contain source code and configuration.",
		Validate:    prefix("PK\x03\x04", "ZIP archive header")},
	{Path: "/public_html.zip", Title: "Site archive exposed", Severity: "high",
		Description: "A site archive is publicly downloadable and may contain source code and configuration.",
		Validate:    prefix("PK\x03\x04", "ZIP archive header")},
	{Path: "/backup.tar.gz", Title: "Backup archive exposed", Severity: "high",
		Description: "A backup archive is publicly downloadable and may contain source code, configuration and data.",
		Validate:    prefix("\x1f\x8b", "gzip archive header")},
	{Path: "/backup.sql", Title: "Database dump exposed", Severity: "high",
		Description: "A SQL dump is publicly downloadable and may contain user data and password hashes.",
		Validate:    sqlDump},
	{Path: "/dump.sql", Title: "Database dump exposed", Severity: "high",
		Description: "A SQL dump is publicly downloadable and may contain user data and password hashes.",
		Validate:    sqlDump},
	{Path: "/db.sql", Title: "Database dump exposed", Severity: "high",
		Description: "A SQL dump is publicly downloadable and may contain user data and password hashes.",
		Validate:    sqlDump},
	{Path: "/database.sql", Title: "Database dump exposed", Severity: "high",
		Description: "A SQL dump is publicly downloadable and may contain user data and password hashes.",
		Validate:    sqlDump},

	// Source code disclosed through backup copies.
	{Path: "/config.php.bak", Title: "PHP configuration backup exposed", Severity: "high",
		Description: "A backup copy of a PHP configuration file is served as plain text and discloses its source, usually including database credentials.",
		Validate:    phpSource},
	{Path: "/config.php.old", Title: "PHP configuration backup exposed", Severity: "high",
		Description: "A backup copy of a PHP configuration file is served as plain text and discloses its source, usually including database credentials.",
		Validate:    phpSource},
	{Path: "/config.php~", Title: "PHP configuration backup exposed", Severity: "high",
		Description: "An editor backup of a PHP configuration file is served as plain text and discloses its source.",
		Validate:    phpSource},
	{Path: "/config.inc.php.bak", Title: "PHP configuration backup exposed", Severity: "high",
		Description: "A backup copy of a PHP configuration file is served as plain text and discloses its source.",
		Validate:    phpSource},

	// Debug and status endpoints.
	{Path: "/phpinfo.php", Title: "phpinfo() page exposed", Severity: "medium",
		Description: "phpinfo() output reveals the PHP version, loaded modules, paths and environment variables. Remove the file.",
		Validate:    htmlAll("phpinfo() output", "PHP Version", "Configuration File")},
	{Path: "/info.php", Title: "phpinfo() page exposed", Severity: "medium",
		Description: "phpinfo() output reveals the PHP version, loaded modules, paths and environment variables. Remove the file.",
		Validate:    htmlAll("phpinfo() output", "PHP Version", "Configuration File")},
	{Path: "/server-status", Title: "Apache server-status exposed", Severity: "medium",
		Description: "The Apache status page is public and reveals live requests, client IPs and virtual hosts. Restrict it to localhost.",
		Validate:    htmlAll("Apache Server Status page", "Apache Server Status for")},
	{Path: "/server-info", Title: "Apache server-info exposed", Severity: "medium",
		Description: "The Apache server-info page is public and reveals modules and configuration. Restrict it to localhost.",
		Validate:    htmlAll("Apache Server Information page", "Apache Server Information")},
	{Path: "/actuator/env", Title: "Spring Boot actuator /env exposed", Severity: "high",
		Description: "The actuator environment endpoint is public and can leak configuration properties and secrets. Restrict actuator endpoints.",
		Validate:    textAll("actuator environment JSON (propertySources)", "propertySources")},
	{Path: "/elmah.axd", Title: "ELMAH error log exposed", Severity: "medium",
		Description: "The ELMAH error log is public and reveals stack traces, paths and request data.",
		Validate:    htmlAll("ELMAH error log page", "Error Log for")},
	{Path: "/trace.axd", Title: "ASP.NET trace viewer exposed", Severity: "medium",
		Description: "The ASP.NET trace viewer is public and reveals request details, cookies and server variables.",
		Validate:    htmlAll("ASP.NET trace page", "Application Trace")},

	// Logs.
	{Path: "/storage/logs/laravel.log", Title: "Laravel log file exposed", Severity: "medium",
		Description: "The application log is publicly readable and often contains stack traces, tokens and personal data.",
		Validate:    textRegexp("Laravel log entries", laravelLogRE)},
	{Path: "/error_log", Title: "PHP error log exposed", Severity: "medium",
		Description: "The PHP error log is publicly readable and reveals file paths and internal errors.",
		Validate:    textRegexp("PHP error log entries", phpErrorRE)},

	// Project and deployment metadata.
	{Path: "/docker-compose.yml", Title: "docker-compose file exposed", Severity: "medium",
		Description: "Deployment configuration is public and may reveal internal services, ports and credentials.",
		Validate:    textAll("docker-compose services definition", "services:")},
	{Path: "/Dockerfile", Title: "Dockerfile exposed", Severity: "low",
		Description: "The Dockerfile is public and reveals base images, build steps and internal paths.",
		Validate:    textRegexp("Dockerfile FROM instruction", dockerFromRE)},
	{Path: "/composer.json", Title: "composer.json exposed", Severity: "low", Confidence: "medium",
		Description: "Dependency metadata is public. Attackers can map exact libraries and versions to known vulnerabilities.",
		Validate:    jsonWith("composer manifest", `"require"`)},
	{Path: "/composer.lock", Title: "composer.lock exposed", Severity: "low", Confidence: "medium",
		Description: "The lock file lists exact dependency versions, which helps attackers pick known vulnerabilities.",
		Validate:    jsonWith("composer lock file", `"packages"`, `"content-hash"`)},
	{Path: "/package.json", Title: "package.json exposed", Severity: "low", Confidence: "medium",
		Description: "Dependency metadata is public. Attackers can map exact libraries and versions to known vulnerabilities.",
		Validate:    jsonWith("npm manifest", `"name"`, `"dependencies"`)},

	// Administration tools.
	{Path: "/adminer.php", Title: "Adminer database tool exposed", Severity: "low", Confidence: "medium",
		Description: "A web database administration tool is reachable from the internet. Restrict it by IP or remove it.",
		Validate:    htmlAll("Adminer login page", "Adminer")},
	{Path: "/phpmyadmin/", Title: "phpMyAdmin exposed", Severity: "low", Confidence: "medium",
		Description: "phpMyAdmin is reachable from the internet. Restrict it by IP or VPN and keep it updated.",
		Validate:    htmlAll("phpMyAdmin page", "phpMyAdmin")},
}
