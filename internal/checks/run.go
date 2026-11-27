package checks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"core/internal/checks/dirlist"
	"core/internal/checks/sensitive"
	"core/internal/checks/sqli"
	"core/internal/checks/tlscheck"
	"core/internal/checks/wp"
	"core/internal/checks/xss"
	"core/internal/httpx"
	"core/internal/terminal"
	"core/pkg/models"
)

// DefaultWorkers is the number of checks that run concurrently. Active checks
// send real traffic to the target, so keep this modest.
const DefaultWorkers = 4

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
	Register(tlscheck.Adapter{})
	Register(sqli.Adapter{})
	Register(xss.Adapter{})
	Register(dirlist.Adapter{})
	Register(sensitive.Adapter{})
	// Register(dorks.Adapter{})//FIXME:
	Register(wp.Adapter{})
}

func buildEndpoint(target string, service models.Service) string {
	scheme := "http"
	if service.Port == 443 || service.Port == 8443 {
		scheme = "https"
	}
	// Default ports are omitted so the Host header matches what a browser sends.
	return scheme + "://" + httpx.HostPort(scheme, target, service.Port) + "/"
}

func checkTimeout(name string) time.Duration {
	switch name {
	case "tls":
		return 5 * time.Second
	case "sqli":
		return 45 * time.Second
	case "xss":
		return 45 * time.Second
	case "directory-listing":
		return 30 * time.Second
	case "dorks":
		return 60 * time.Second // generation + bounded DuckDuckGo Lite requests
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

type job struct {
	chk      Check
	service  models.Service
	endpoint string
}

// Run executes all applicable checks with the default concurrency.
func Run(
	ctx context.Context,
	target string,
	services []models.Service,
) ([]models.Finding, error) {
	return RunWithWorkers(ctx, target, services, DefaultWorkers)
}

// RunWithWorkers runs every applicable (service, check) pair on a bounded
// worker pool. Findings are returned in the same order a sequential run
// would produce, regardless of which job finishes first.
func RunWithWorkers(
	ctx context.Context,
	target string,
	services []models.Service,
	workers int,
) ([]models.Finding, error) {
	if workers <= 0 {
		workers = DefaultWorkers
	}

	var jobs []job
	for _, service := range services {
		for _, chk := range registry {
			if chk.ShouldRun(service) {
				jobs = append(jobs, job{
					chk:      chk,
					service:  service,
					endpoint: buildEndpoint(target, service),
				})
			}
		}
	}

	results := make([][]models.Finding, len(jobs))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

dispatch:
	for i, j := range jobs {
		select {
		case <-ctx.Done():
			break dispatch
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			defer func() { <-sem }()

			checkCtx, cancel := context.WithTimeout(ctx, checkTimeout(j.chk.Name()))
			defer cancel()

			found, err := execute(checkCtx, j.chk, j.endpoint, j.service)
			if err != nil {
				terminal.ColoredError(j.chk.Name()+" assessment failed:", err)
			}
			results[i] = found
		}(i, j)
	}
	wg.Wait()

	var findings []models.Finding
	for _, r := range results {
		findings = append(findings, r...)
	}
	return findings, nil
}
