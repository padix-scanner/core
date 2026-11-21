package dorks

import (
	"context"
	"strings"

	"core/pkg/models"
)

// Adapter exposes the dork generator through the checks registry.
//
// The check is host-level (OSINT). It runs once per open HTTP service so that
// it participates in the normal assessment loop; findings use stable IDs and
// are therefore cheap to de-duplicate downstream.
type Adapter struct{}

func (Adapter) Name() string     { return "dorks" }
func (Adapter) Category() string { return "dorks" }

func (Adapter) ShouldRun(s models.Service) bool {
	// Run only against an open HTTP service so the check is executed a
	// bounded number of times and only when a web presence is likely.
	return s.Name == "HTTP" && s.State == "open"
}

func (Adapter) Assess(ctx context.Context, endpoint string, service models.Service) ([]models.Finding, error) {
	// endpoint is of the form scheme://host:port/; we only need the host.
	// The target hostname was already validated by the CLI.
	host := hostFromEndpoint(endpoint)
	if host == "" {
		return nil, nil
	}
	return Assess(host), nil
}

func hostFromEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")
	if idx := strings.IndexAny(endpoint, "/:#"); idx != -1 {
		endpoint = endpoint[:idx]
	}
	return strings.Trim(endpoint, ".")
}
