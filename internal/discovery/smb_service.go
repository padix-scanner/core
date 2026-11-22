package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverSMBService detects an SMB service on the target (port 445).
func discoverSMBService(target string) ([]models.Service, error) {
	const port = 445

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceSMB),
		State:      "open",
		Confidence: "high",
	}}, nil
}
