package checks

import (
	"context"
	"net"
	"strconv"
	"time"

	"core/internal/checks/sqli"
	"core/internal/checks/xss"
	"core/internal/terminal"
	"core/pkg/models"
)

// Run performs the general vulnerability assessment against discovered
// services. It covers SQL injection and reflected cross-site scripting
func Run(
	ctx context.Context,
	target string,
	services []models.Service,
) ([]models.Finding, error) {
	var findings []models.Finding

	for _, service := range services {
		if service.Name != "HTTP" || service.State != "open" {
			continue
		}

		scheme := "http"
		if service.Port == 443 || service.Port == 8443 {
			scheme = "https"
		}
		endpoint := scheme + "://" + net.JoinHostPort(target, strconv.Itoa(service.Port)) + "/"

		serviceCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()

		sqliFindings, sqliErr := sqli.Assess(serviceCtx, endpoint, sqli.DefaultConfig())
		if sqliErr != nil {
			terminal.ColoredError("SQLi assessment failed:", sqliErr)
		} else {
			findings = append(findings, sqliFindings...)
		}

		xssFindings, xssErr := xss.Assess(serviceCtx, endpoint, xss.DefaultConfig())
		if xssErr != nil {
			terminal.ColoredError("XSS assessment failed:", xssErr)
		} else {
			findings = append(findings, xssFindings...)
		}
	}

	return findings, nil
}
