package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverDNSService detects a DNS service on the target (TCP port 53).
// Only TCP is probed here; UDP DNS is outside the scope of the TCP discovery path.
func discoverDNSService(target string) ([]models.Service, error) {
	const port = 53

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceDNS),
		State:      "open",
		Confidence: "high",
	}}, nil
}
