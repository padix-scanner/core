package checks

import (
	"context"
	"net"
	"strconv"
	"time"

	"core/internal/checks/dirlist"
	"core/internal/checks/exposedservices"
	"core/internal/checks/sqli"
	"core/internal/checks/xss"
	"core/internal/terminal"
	"core/pkg/models"
)

// Check is a single vulnerability assessment. Implementations are registered
// in the package-level registry and applied to every matching service, so
// adding a new check only requires implementing this interface and registering
// it in init.
type Check interface {
	// Name is a short stable identifier used in logs and finding IDs.
	Name() string
	// Category is the finding category emitted by this check.
	Category() string
	// ShouldRun reports whether the check applies to the given service.
	ShouldRun(service models.Service) bool
	// Assess runs the check. Implementations may use either the endpoint URL
	// or the full service object depending on what the check needs.
	Assess(ctx context.Context, endpoint string, service models.Service) ([]models.Finding, error)
}

var registry []Check

// Register appends c to the check registry.
func Register(c Check) {
	registry = append(registry, c)
}

func init() {
	Register(sqli.Adapter{})
	Register(xss.Adapter{})
	Register(dirlist.Adapter{})
	Register(exposedservices.Adapter{})
}

// buildEndpoint derives the assessment URL for an HTTP(S) service.
func buildEndpoint(target string, service models.Service) string {
	scheme := "http"
	if service.Port == 443 || service.Port == 8443 {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(target, strconv.Itoa(service.Port)) + "/"
}

// Run performs the general vulnerability assessment against discovered
// services by applying every registered check to each matching service.
func Run(
	ctx context.Context,
	target string,
	services []models.Service,
) ([]models.Finding, error) {
	var findings []models.Finding

	for _, service := range services {
		for _, chk := range registry {
			if !chk.ShouldRun(service) {
				continue
			}

			endpoint := buildEndpoint(target, service)
			serviceCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)

			checkFindings, err := chk.Assess(serviceCtx, endpoint, service)
			cancel()

			if err != nil {
				terminal.ColoredError(chk.Name()+" assessment failed:", err)
				continue
			}
			findings = append(findings, checkFindings...)
		}
	}

	return findings, nil
}
