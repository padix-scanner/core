package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"

	"core/pkg/models"
)

// discoverMySQLService detects a MySQL service on the target (port 3306).
// It performs a TCP connect and optionally reads the server greeting packet.
func discoverMySQLService(target string) ([]models.Service, error) {
	const port = 3306

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceMySQL),
		State:      "open",
		Confidence: "high",
	}

	// Best-effort read of the initial handshake (version string is null-terminated
	// after the protocol version byte and length fields).
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err == nil && n > 5 {
		// Skip packet length (3) + sequence (1) + protocol version (1); version follows.
		i := 5
		for i < n && buf[i] != 0 {
			i++
		}
		if i > 5 {
			version := string(buf[5:i])
			if strings.ContainsAny(version, "0123456789.") {
				service.Product = "MySQL " + version
			}
		}
	}

	return []models.Service{service}, nil
}

// discoverPostgreSQLService detects a PostgreSQL service on the target (port 5432).
func discoverPostgreSQLService(target string) ([]models.Service, error) {
	return discoverDatabaseService(target, 5432, ServicePostgres)
}

// discoverMSSQLService detects a Microsoft SQL Server service on the target (port 1433).
func discoverMSSQLService(target string) ([]models.Service, error) {
	return discoverDatabaseService(target, 1433, ServiceMSSQL)
}

// discoverOracleService detects an Oracle Database listener on the target (port 1521).
func discoverOracleService(target string) ([]models.Service, error) {
	return discoverDatabaseService(target, 1521, ServiceOracle)
}

func discoverDatabaseService(target string, port int, name serviceName) ([]models.Service, error) {
	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	return []models.Service{{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(name),
		State:      "open",
		Confidence: "high",
	}}, nil
}
