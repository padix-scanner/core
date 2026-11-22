package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"core/pkg/models"
)

// discoverFTPService detects an FTP service on the target.
func discoverFTPService(target string) ([]models.Service, error) {
	const port = 21

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout(
		"tcp",
		address,
		3*time.Second,
	)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceFTP),
		State:      "open",
		Confidence: "high",
	}

	// Read FTP welcome banner.
	if err := conn.SetReadDeadline(
		time.Now().Add(3 * time.Second),
	); err != nil {
		return []models.Service{service}, nil
	}

	reader := bufio.NewReader(conn)

	banner, err := reader.ReadString('\n')
	if err == nil {
		banner = strings.TrimSpace(banner)

		// FTP server responses normally begin with a three-digit code.
		if len(banner) >= 3 &&
			banner[0] >= '0' && banner[0] <= '9' &&
			banner[1] >= '0' && banner[1] <= '9' &&
			banner[2] >= '0' && banner[2] <= '9' {

			service.Product = banner
		}
	}

	return []models.Service{service}, nil
}
