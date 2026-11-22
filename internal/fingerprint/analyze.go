package fingerprint

import (
	"net/http"
	"strings"

	"core/pkg/models"
)

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

	// Nginx-specific internal headers.
	nginxHeaders := []string{
		"X-Accel-Redirect",
		"X-Accel-Expires",
		"X-Accel-Limit-Rate",
		"X-Accel-Buffering",
		"X-Accel-Charset",
		"X-Accel-Charset-Mapping",
	}

	for _, h := range nginxHeaders {
		if resp.Header.Get(h) != "" {
			add(
				"Nginx",
				"",
				"web-server",
				"high",
				h+" header",
			)

			break
		}
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
		{"nginx-plus", "Nginx Plus"},
		{"tengine", "Tengine"},
		{"openresty", "OpenResty"},
		{"apache", "Apache"},
		{"microsoft-iis", "Microsoft IIS"},
		{"caddy", "Caddy"},
		{"lighttpd", "Lighttpd"},
		{"litespeed", "LiteSpeed"},
		{"cloudflare", "Cloudflare"},
		{"netlify", "Netlify"},
		{"vercel", "Vercel"},
		{"github", "GitHub Pages"},
		{"tomcat", "Apache Tomcat"},
		{"jetty", "Jetty"},
		{"gunicorn", "Gunicorn"},
		{"uwsgi", "uWSGI"},
		{"resin", "Resin"},
		{"glassfish", "GlassFish"},
		{"wildfly", "WildFly"},
		{"weblogic", "WebLogic"},
		{"websphere", "WebSphere"},
		{"iis", "Microsoft IIS"},
	}

	for _, server := range servers {
		if strings.Contains(lower, server.pattern) {
			return server.name, extractVersion(value)
		}
	}

	return value, extractVersion(value)
}
