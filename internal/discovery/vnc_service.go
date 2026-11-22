package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverVNCService detects a VNC service on the target (port 5900).
func discoverVNCService(target string) ([]models.Service, error) {
	const port = 5900

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceVNC),
		State:      "open",
		Confidence: "high",
	}}, nil
}
