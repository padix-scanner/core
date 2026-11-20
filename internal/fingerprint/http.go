package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"core/pkg/models"
)

const maxResponseBody = 1 << 20 // 1 MB

var versionPattern = regexp.MustCompile(
	`(?i)(?:/|\s|v)([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
)

type httpTarget struct {
	port   int
	scheme string
}

// FingerprintHTTP identifies technologies exposed by HTTP services.
//
// Pass the ports discovered by the discovery module.
// Individual connection failures are ignored.
func FingerprintHTTP(
	ctx context.Context,
	target string,
	port int,
) ([]models.Technology, error) {
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	target = strings.TrimSpace(target)

	// Prevent accidentally treating a URL as a hostname.
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	if strings.ContainsAny(target, "/?#@") {
		return nil, fmt.Errorf("invalid HTTP fingerprint target")
	}

	var technologies []models.Technology

	seen := make(map[string]bool)

	var endpoint httpTarget

	switch port {
	case 80, 8080:
		endpoint = httpTarget{port: port, scheme: "http"}

	case 443, 8443:
		endpoint = httpTarget{port: port, scheme: "https"}

	default:
		return technologies, fmt.Errorf("not found port")
	}

	found := fingerprintEndpoint(
		ctx,
		target,
		endpoint,
	)

	for _, tech := range found {
		key := strings.ToLower(
			tech.Name + ":" + tech.Version,
		)

		if seen[key] {
			continue
		}

		seen[key] = true
		technologies = append(technologies, tech)
	}

	return technologies, nil
}

func fingerprintEndpoint(
	ctx context.Context,
	target string,
	endpoint httpTarget,
) []models.Technology {
	address := net.JoinHostPort(
		target,
		strconv.Itoa(endpoint.port),
	)

	url := fmt.Sprintf(
		"%s://%s/",
		endpoint.scheme,
		address,
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: target,
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 4 * time.Second,
	}

	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,

		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		return nil
	}

	req.Header.Set(
		"User-Agent",
		"Padix-Scanner/0.1.1",
	)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(
		io.LimitReader(resp.Body, maxResponseBody),
	)

	return analyzeHTTPResponse(resp, body)
}

// analyzeHTTPResponse extracts technology information from an HTTP response.
func analyzeHTTPResponse(
	resp *http.Response,
	body []byte,
) []models.Technology {
	var technologies []models.Technology

	seen := make(map[string]bool)

	add := func(
		name string,
		version string,
		category string,
		confidence string,
		source string,
	) {
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)

		if name == "" {
			return
		}

		key := strings.ToLower(name + ":" + version)

		if seen[key] {
			return
		}

		seen[key] = true

		technologies = append(
			technologies,
			models.Technology{
				Name:       name,
				Version:    version,
				Category:   category,
				Confidence: confidence,
				Source:     source,
			},
		)
	}

	// HTTP Server header.
	server := resp.Header.Get("Server")

	if server != "" {
		name, version := identifyServer(server)

		add(
			name,
			version,
			"web-server",
			"high",
			"Server header",
		)
	}

	// X-Powered-By header.
	poweredBy := resp.Header.Get("X-Powered-By")

	if poweredBy != "" {
		detectPoweredBy(poweredBy, add)
	}

	// ASP.NET headers.
	aspVersion := resp.Header.Get("X-AspNet-Version")

	if aspVersion != "" {
		add(
			"ASP.NET",
			aspVersion,
			"framework",
			"high",
			"X-AspNet-Version header",
		)
	}

	aspMVC := resp.Header.Get("X-AspNetMvc-Version")

	if aspMVC != "" {
		add(
			"ASP.NET MVC",
			aspMVC,
			"framework",
			"high",
			"X-AspNetMvc-Version header",
		)
	}

	// HTML inspection.
	html := strings.ToLower(string(body))

	detectHTMLTechnologies(html, add)

	return technologies
}

// identifyServer identifies common web servers.
func identifyServer(value string) (string, string) {
	value = strings.TrimSpace(value)

	lower := strings.ToLower(value)

	servers := []struct {
		pattern string
		name    string
	}{
		{"nginx", "Nginx"},
		{"apache", "Apache"},
		{"microsoft-iis", "Microsoft IIS"},
		{"caddy", "Caddy"},
		{"lighttpd", "Lighttpd"},
		{"openresty", "OpenResty"},
		{"litespeed", "LiteSpeed"},
		{"cloudflare", "Cloudflare"},
	}

	for _, server := range servers {
		if strings.Contains(lower, server.pattern) {
			return server.name, extractVersion(value)
		}
	}

	return value, extractVersion(value)
}

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
