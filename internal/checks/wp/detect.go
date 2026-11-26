package wp

import (
	"regexp"
	"strings"
)

var (
	// The generator meta tag may list name before content or the reverse.
	generatorRE    = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	generatorRevRE = regexp.MustCompile(`(?is)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']`)

	wpContentRE    = regexp.MustCompile(`(?i)/wp-content/`)
	wpIncludesRE   = regexp.MustCompile(`(?i)/wp-includes/`)
	versionTokenRE = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)*$`)
)

// generatorContent returns the content of the generator meta tag, if any.
func generatorContent(body string) string {
	if m := generatorRE.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := generatorRevRE.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// Detect reports whether an HTML body looks like a WordPress site and returns
// a short, human-readable list of the markers that matched. It is purely
// passive (no network access), so other packages such as fingerprint can call
// it on a page they already fetched.
func Detect(body string) (found bool, evidence string) {
	lower := strings.ToLower(body)

	var reasons []string
	if wpContentRE.MatchString(lower) {
		reasons = append(reasons, "/wp-content/ present")
	}
	if wpIncludesRE.MatchString(lower) {
		reasons = append(reasons, "/wp-includes/ present")
	}
	if gen := generatorContent(body); gen != "" &&
		strings.Contains(strings.ToLower(gen), "wordpress") {
		reasons = append(reasons, "generator meta: "+gen)
	}
	if strings.Contains(lower, "wp-json") || strings.Contains(lower, "wp-emoji") {
		reasons = append(reasons, "WordPress-specific script/JSON markers")
	}

	if len(reasons) == 0 {
		return false, ""
	}
	return true, strings.Join(reasons, "; ")
}

// ExtractVersion returns the WordPress version advertised in the generator
// meta tag (for example "WordPress 6.4.2" → "6.4.2") and where it came from.
// It returns empty strings when the page does not expose a version.
func ExtractVersion(body string) (version, source string) {
	gen := generatorContent(body)
	if gen == "" || !strings.Contains(strings.ToLower(gen), "wordpress") {
		return "", ""
	}
	for _, field := range strings.Fields(gen) {
		if versionTokenRE.MatchString(field) {
			return field, "generator meta tag"
		}
	}
	return "", ""
}