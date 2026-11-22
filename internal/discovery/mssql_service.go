package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverMSSQLService detects a Microsoft SQL Server service on the target (port 1433).
func discoverMSSQLService(target string) ([]models.Service, error) {
	const port = 1433

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceMSSQL),
		State:      "open",
		Confidence: "high",
	}}, nil
}
