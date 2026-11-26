package fingerprint

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"core/internal/httpx"
	"core/pkg/constants"
	"core/pkg/models"
)

const maxResponseBody = 1 << 20 // 1 MB

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

	rawURL := fmt.Sprintf(
		"%s://%s/",
		endpoint.scheme,
		httpx.HostPort(endpoint.scheme, target, endpoint.port),
	)

	start, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	// Follow same-site redirects (http→https, www↔apex) so headers and HTML of
	// the page that is really served are analysed, not an empty 301 body.
	// Certificate errors are ignored here; they are reported by the TLS check.
	client := httpx.NewClient(
		8*time.Second,
		func(next *url.URL) bool { return httpx.SameSite(next, start) },
	)
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		rawURL,
		nil,
	)
	if err != nil {
		return nil
	}

	req.Header.Set(
		"User-Agent",
		constants.AppUserAgent,
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
