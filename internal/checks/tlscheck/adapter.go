// Package tlscheck turns the TLS data collected during discovery into
// findings. It sends no network traffic of its own.
package tlscheck

import (
	"context"
	"fmt"
	"time"

	"core/pkg/models"
)

// Adapter exposes TLS/certificate assessment through the checks registry.
type Adapter struct{}

func (Adapter) Name() string     { return "tls" }
func (Adapter) Category() string { return "tls" }

func (Adapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open" && s.TLSVersion != ""
}

func (Adapter) Assess(_ context.Context, endpoint string, s models.Service) ([]models.Finding, error) {
	var out []models.Finding

	subject := s.TLSSubject
	if subject == "" {
		subject = "N/A"
	}
	base := fmt.Sprintf("Endpoint: %s\nSubject: %s\nProtocol: %s", endpoint, subject, s.TLSVersion)

	if s.TLSVerifyError != "" {
		out = append(out, models.Finding{
			ID:          fmt.Sprintf("tls-cert-invalid-%d", s.Port),
			Title:       "TLS certificate validation failed",
			Category:    "tls",
			Severity:    "medium",
			Status:      "vulnerable",
			Confidence:  "high",
			Description: "The certificate presented by the server is not trusted for this host. Clients will show warnings or refuse to connect, and users may be trained to click through them.",
			Evidence:    base + "\nError: " + s.TLSVerifyError,
		})
	}

	if expiry, err := time.Parse(time.RFC3339, s.TLSExpiry); err == nil {
		now := time.Now()
		switch {
		case expiry.Before(now):
			out = append(out, models.Finding{
				ID:          fmt.Sprintf("tls-cert-expired-%d", s.Port),
				Title:       "TLS certificate has expired",
				Category:    "tls",
				Severity:    "high",
				Status:      "vulnerable",
				Confidence:  "high",
				Description: "The server's certificate is past its expiry date. Renew it.",
				Evidence:    base + "\nExpired: " + s.TLSExpiry,
			})
		case expiry.Before(now.AddDate(0, 0, 30)):
			out = append(out, models.Finding{
				ID:          fmt.Sprintf("tls-cert-expiring-%d", s.Port),
				Title:       "TLS certificate expires within 30 days",
				Category:    "tls",
				Severity:    "low",
				Status:      "potential",
				Confidence:  "high",
				Description: "The certificate expires soon. Make sure renewal is automated or scheduled.",
				Evidence:    base + "\nExpires: " + s.TLSExpiry,
			})
		}
	}

	switch s.TLSVersion {
	case "TLS 1.0", "TLS 1.1":
		out = append(out, models.Finding{
			ID:          fmt.Sprintf("tls-weak-protocol-%d", s.Port),
			Title:       "Deprecated TLS protocol version in use",
			Category:    "tls",
			Severity:    "medium",
			Status:      "vulnerable",
			Confidence:  "high",
			Description: "The server negotiated " + s.TLSVersion + ", which is deprecated (RFC 8996). Require TLS 1.2 or newer.",
			Evidence:    base,
		})
	}

	return out, nil
}