
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"core/pkg/models"
)

type Result struct {
	Hostname string
	IP       string
	Services []models.Service
}

var defaultPorts = []struct {
	port int
	name string
}{
	{80, "HTTP"},
	{443, "HTTPS"},
}

// Run performs basic DNS and web service discovery.
func Run(target string) (Result, error) {
	result := Result{
		Hostname: target,
		Services: make([]models.Service, 0),
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	// Resolve target.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return result, fmt.Errorf("DNS resolution failed: %w", err)
	}

	if len(ips) == 0 {
		return result, fmt.Errorf("no IP addresses found")
	}

	result.IP = ips[0].IP.String()

	// Discover standard web services.
	for _, port := range defaultPorts {
		service := discoverWebService(target, port.port, port.name)

		if service != nil {
			result.Services = append(
				result.Services,
				*service,
			)
		}
	}

	return result, nil
}

func discoverWebService(
	target string,
	port int,
	name string,
) *models.Service {
	address := net.JoinHostPort(
		target,
		strconv.Itoa(port),
	)

	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil
	}
	conn.Close()

	service := &models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       name,
		State:      "open",
		Confidence: "high",
	}

	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: target,
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 3 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,

		// Do not follow redirects.
		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	defer transport.CloseIdleConnections()

	req, err := http.NewRequest(
		http.MethodHead,
		fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(target, strconv.Itoa(port))),
		nil,
	)
	if err != nil {
		return service
	}

	resp, err := client.Do(req)
	if err != nil {
		return service
	}
	defer resp.Body.Close()

	service.StatusCode = resp.StatusCode
	service.Product = strings.TrimSpace(
		resp.Header.Get("Server"),
	)

	if port == 443 && resp.TLS != nil {
		service.TLSVersion = tlsVersionName(
			resp.TLS.Version,
		)

		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]

			service.TLSSubject = cert.Subject.String()
			service.TLSExpiry = cert.NotAfter.UTC().Format(
				time.RFC3339,
			)
		}
	}

	return service
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
