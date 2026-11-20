package discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"core/internal/terminal"
	"core/pkg/models"
)

type Result struct {
	Hostname string
	IP       string
	Services []models.Service
}

// Run performs DNS and common TCP service discovery.
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

	// Discover services and their associated ports.
	for _, service := range defaultServices {

		found := discoverService(
			target,
			service.name,
		)

		result.Services = append(
			result.Services,
			found...,
		)

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

		// TODO: Implement other services.

	}
	if err != nil {
		terminal.ColoredError(fmt.Printf("failed to discover %s services: %v", serviceName, err))
		return nil
	}

	return services
}
