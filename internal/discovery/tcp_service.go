package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverTCPService performs a bounded TCP connect check for services that
// do not yet have a protocol-specific banner probe.
func discoverTCPService(target string, name serviceName) ([]models.Service, error) {
	var ports []int
	for _, configured := range defaultServices {
		if configured.name == name {
			ports = append(ports, configured.ports...)
		}
	}

	services := make([]models.Service, 0, len(ports))
	for _, port := range ports {
		address := net.JoinHostPort(target, fmt.Sprint(port))
		conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.Close()

		services = append(services, models.Service{
			Port:       port,
			Protocol:   "TCP",
			Name:       string(name),
			State:      "open",
			Confidence: "high",
		})
	}
	return services, nil
}
