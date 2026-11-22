package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverPostgreSQLService detects a PostgreSQL service on the target (port 5432).
func discoverPostgreSQLService(target string) ([]models.Service, error) {
	const port = 5432

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServicePostgres),
		State:      "open",
		Confidence: "high",
	}}, nil
}
