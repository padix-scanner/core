package fingerprint

import (
	"regexp"
	"strings"
)

var versionPattern = regexp.MustCompile(
	`(?i)(?:/|\s|v)([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
)

// detectPoweredBy identifies frameworks from X-Powered-By.
func detectPoweredBy(
	value string,
	add func(string, string, string, string, string),
) {
	lower := strings.ToLower(value)

	switch {
	case strings.Contains(lower, "express"):
		add(
			"Express",
			extractVersion(value),
			"framework",
			"high",
			"X-Powered-By header",
		)

	case strings.Contains(lower, "php"):
		add(
			"PHP",
			extractVersion(value),
			"language",
			"high",
			"X-Powered-By header",
		)

	case strings.Contains(lower, "asp.net"):
		add(
			"ASP.NET",
			extractVersion(value),
			"framework",
			"high",
			"X-Powered-By header",
		)

	case strings.Contains(lower, "servlet"):
		add(
			"Java Servlet",
			extractVersion(value),
			"framework",
			"medium",
			"X-Powered-By header",
		)

	default:
		add(
			value,
			extractVersion(value),
			"framework",
			"medium",
			"X-Powered-By header",
		)
	}
}

// detectHTMLTechnologies identifies common CMS and frameworks.
func detectHTMLTechnologies(
	html string,
	add func(string, string, string, string, string),
) {
	// CMS detection.
	cmsPatterns := []struct {
		pattern  string
		name     string
		category string
	}{
		{
			`<meta[^>]+generator[^>]+wordpress`,
			"WordPress",
			"cms",
		},
		{
			`/wp-content/`,
			"WordPress",
			"cms",
		},
		{
			`<meta[^>]+generator[^>]+drupal`,
			"Drupal",
			"cms",
		},
		{
			`/sites/default/files/`,
			"Drupal",
			"cms",
		},
		{
			`<meta[^>]+generator[^>]+joomla`,
			"Joomla",
			"cms",
		},
		{
			`/media/system/js/`,
			"Joomla",
			"cms",
		},
		{
			`<h1>nginx</h1>`,
			"Nginx",
			"web-server",
		},
		{
			`nginx`,
			"Nginx",
			"web-server",
		},
	}

	for _, item := range cmsPatterns {
		matched, _ := regexp.MatchString(
			item.pattern,
			html,
		)

		if matched {
			add(
				item.name,
				"",
				item.category,
				"medium",
				"HTML content",
			)
		}
	}

	// Framework detection.
	frameworkPatterns := []struct {
		pattern string
		name    string
	}{
		{`__next`, "Next.js"},
		{`__nuxt`, "Nuxt"},
		{`ng-version=`, "Angular"},
		{`data-reactroot`, "React"},
		{`data-v-[a-f0-9]+`, "Vue.js"},
		{`laravel_session`, "Laravel"},
		{`csrfmiddlewaretoken`, "Django"},
		{`_rails_session`, "Ruby on Rails"},
		{`blazor`, "Blazor"},
	}

	for _, item := range frameworkPatterns {
		matched, _ := regexp.MatchString(
			item.pattern,
			html,
		)

		if matched {
			add(
				item.name,
				"",
				"framework",
				"medium",
				"HTML content",
			)
		}
	}
}

// extractVersion extracts a version explicitly exposed in a value.
func extractVersion(value string) string {
	match := versionPattern.FindStringSubmatch(value)

	if len(match) < 2 {
		return ""
	}

	return match[1]
}
