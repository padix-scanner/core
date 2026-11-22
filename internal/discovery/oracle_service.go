package discovery

import (
	"fmt"
	"net"
	"time"

	"core/pkg/models"
)

// discoverOracleService detects an Oracle Database listener on the target (port 1521).
func discoverOracleService(target string) ([]models.Service, error) {
	const port = 1521

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceOracle),
		State:      "open",
		Confidence: "high",
	}}, nil
}
