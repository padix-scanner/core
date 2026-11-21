package checks

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"core/internal/checks/dirlist"
	"core/internal/checks/dorks"
	"core/internal/checks/exposedservices"
	"core/internal/checks/sqli"
	"core/internal/checks/wp"
	"core/internal/checks/xss"
	"core/internal/terminal"
	"core/pkg/models"
)

type Check interface {
	Name() string
	Category() string
	ShouldRun(service models.Service) bool
	Assess(ctx context.Context, endpoint string, service models.Service) ([]models.Finding, error)
}

var registry []Check

func Register(c Check) {
	registry = append(registry, c)
}

func init() {
	Register(sqli.Adapter{})
	Register(xss.Adapter{})
	Register(dirlist.Adapter{})
	Register(exposedservices.Adapter{})
	Register(dorks.Adapter{})
	Register(wp.Adapter{})
}

func buildEndpoint(target string, service models.Service) string {
	scheme := "http"
	if service.Port == 443 || service.Port == 8443 {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(target, strconv.Itoa(service.Port)) + "/"
}

func checkTimeout(name string) time.Duration {
	switch name {
	case "sqli":
		return 45 * time.Second
	case "xss":
		return 45 * time.Second
	case "directory-listing":
		return 30 * time.Second
	case "dorks":
		return 5 * time.Second // pure generation, no network
	case "wordpress":
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

// execute isolates an individual check from panics.
func execute(
	ctx context.Context,
	chk Check,
	endpoint string,
	service models.Service,
) (findings []models.Finding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			findings = nil
			err = fmt.Errorf("panic recovered: %v", recovered)
		}
	}()

	return chk.Assess(ctx, endpoint, service)
}

func Run(
	ctx context.Context,
	target string,
	services []models.Service,
) ([]models.Finding, error) {
	var findings []models.Finding

	for _, service := range services {
		if err := ctx.Err(); err != nil {
			break
		}

		for _, chk := range registry {
			if err := ctx.Err(); err != nil {
				break
			}

			if !chk.ShouldRun(service) {
				continue
			}

			endpoint := buildEndpoint(target, service)
			serviceCtx, cancel := context.WithTimeout(
				ctx,
				checkTimeout(chk.Name()),
			)

			checkFindings, err := execute(
				serviceCtx,
				chk,
				endpoint,
				service,
			)

			cancel()

			findings = append(findings, checkFindings...)

			if err != nil {
				terminal.ColoredError(
					chk.Name()+" assessment failed:",
					err,
				)
				continue
			}
		}
	}

	return findings, nil
}
