package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverRDPService detects a Remote Desktop (RDP) service on the target (port 3389).
func discoverRDPService(target string) ([]models.Service, error) {
	const port = 3389

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceRDP),
		State:      "open",
		Confidence: "high",
	}}, nil
}
