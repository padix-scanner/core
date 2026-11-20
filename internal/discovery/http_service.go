package discovery

import (
	"context"
	"core/internal/fingerprint"
	"core/internal/terminal"
	"core/pkg/models"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func discoverHttpService(target string) ([]models.Service, error) {
	var services []models.Service
	var httpPorts []int
	// Collect HTTP ports.
	for _, service := range defaultServices {
		if service.name == ServiceHTTP {
			httpPorts = append(httpPorts, service.ports...)
		}
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()
	// Discover HTTP services.
	for _, port := range httpPorts {
		useTLS := port == 443 || port == 8443
		service := &models.Service{
			Port:       port,
			Protocol:   "TCP",
			Name:       string(ServiceHTTP),
			State:      "open",
			Confidence: "high",
		}

		if err := probeHTTP(target, port, useTLS, service); err != nil {
			continue
		}
		// Fingerprint discovered HTTP service.
		technologies, err := fingerprint.FingerprintHTTP(
			ctx,
			target,
			port,
		)

		if err != nil {
			terminal.ColoredError(
				"HTTP fingerprinting failed:", err,
			)
		} else {
			service.Technologies = technologies
		}

		services = append(services, *service)
	}

	return services, nil

}

// probeHTTP collects basic HTTP and TLS information.
func probeHTTP(
	target string,
	port int,
	useTLS bool,
	service *models.Service,
) error {
	scheme := "http"

	transport := &http.Transport{}

	if useTLS {
		scheme = "https"

		transport.TLSClientConfig = &tls.Config{
			ServerName: target,
			MinVersion: tls.VersionTLS12,
		}

		transport.TLSHandshakeTimeout = 3 * time.Second
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	defer transport.CloseIdleConnections()

	url := fmt.Sprintf(
		"%s://%s/",
		scheme,
		net.JoinHostPort(target, strconv.Itoa(port)),
	)

	req, err := http.NewRequest(
		http.MethodHead,
		url,
		nil,
	)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	service.StatusCode = resp.StatusCode

	service.Product = strings.TrimSpace(
		resp.Header.Get("Server"),
	)

	if useTLS && resp.TLS != nil {
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
	return nil
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
