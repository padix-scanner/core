package discovery

import (
	"context"
	"core/internal/fingerprint"
	"core/internal/terminal"
	"core/pkg/constants"
	"core/pkg/models"
	"crypto/tls"
	"crypto/x509"
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
//
// Certificates are NOT verified during the handshake: a service with an
// expired, self-signed or mismatched certificate is still a discovered
// service. Verification is performed separately and stored in
// service.TLSVerifyError so it can be reported.
func probeHTTP(
	target string,
	port int,
	useTLS bool,
	service *models.Service,
) error {
	scheme := "http"

	transport := &http.Transport{
		TLSHandshakeTimeout: 3 * time.Second,
	}

	if useTLS {
		scheme = "https"

		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS10, // still reach legacy servers
			// #nosec G402 -- intentional: see function comment.
			InsecureSkipVerify: true,
		}
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
	req.Header.Set("User-Agent", constants.AppUserAgent)

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

			service.TLSVerifyError = verifyCertificate(
				resp.TLS.PeerCertificates,
				target,
			)
		}
	}
	return nil
}

// verifyCertificate validates the presented chain for host against the system
// roots. It returns an empty string when the certificate is trusted.
func verifyCertificate(chain []*x509.Certificate, host string) string {
	if len(chain) == 0 {
		return ""
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
	})
	if err != nil {
		return err.Error()
	}
	return ""
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
