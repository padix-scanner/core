package discovery

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"core/internal/terminal"
	"core/pkg/models"
)

// DefaultWorkers is the number of services probed concurrently.
const DefaultWorkers = 8

type Result struct {
	Hostname string
	IP       string
	Services []models.Service
}

// Run performs DNS and common TCP service discovery with the default
// concurrency.
func Run(target string) (Result, error) {
	return RunWithWorkers(target, DefaultWorkers)
}

// RunWithWorkers is like Run but lets the caller bound concurrency.
// The order of the returned services always follows defaultServices.
func RunWithWorkers(target string, workers int) (Result, error) {
	if workers <= 0 {
		workers = DefaultWorkers
	}

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

	// Probe every known service concurrently. Each goroutine writes only to
	// its own slot, so no lock is needed and ordering stays deterministic.
	found := make([][]models.Service, len(defaultServices))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, svc := range defaultServices {
		wg.Add(1)
		sem <- struct{}{}

		go func(i int, name serviceName) {
			defer wg.Done()
			defer func() { <-sem }()
			found[i] = discoverService(target, name)
		}(i, svc.name)
	}
	wg.Wait()

	for _, services := range found {
		result.Services = append(result.Services, services...)
	}

	return result, nil
}

// discoverService checks whether a known TCP service is reachable.
func discoverService(
	target string,
	serviceName serviceName,
) []models.Service {
	var services []models.Service
	var err error
	switch serviceName {
	case ServiceHTTP:
		services, err = discoverHttpService(target)
	case ServiceSSH:
		services, err = discoverSSHService(target)
	case ServiceFTP:
		services, err = discoverFTPService(target)
	case ServiceSMTP:
		services, err = discoverSMTPService(target)
	case ServiceSMB:
		services, err = discoverSMBService(target)
	case ServiceRDP:
		services, err = discoverRDPService(target)
	case ServiceVNC:
		services, err = discoverVNCService(target)
	case ServiceRedis:
		services, err = discoverRedisService(target)
	case ServiceMySQL:
		services, err = discoverMySQLService(target)
	case ServicePostgres:
		services, err = discoverPostgreSQLService(target)
	case ServiceMSSQL:
		services, err = discoverMSSQLService(target)
	case ServiceOracle:
		services, err = discoverOracleService(target)
	case ServicePOP3:
		services, err = discoverPOP3Service(target)
	case ServiceIMAP:
		services, err = discoverIMAPService(target)
	case ServiceDNS:
		services, err = discoverDNSService(target)
	default:
		services, err = discoverTCPService(target, serviceName)
	}
	if err != nil {
		terminal.ColoredError(
			fmt.Sprintf("failed to discover %s services: %v", serviceName, err),
		)
		return nil
	}

	return services
}