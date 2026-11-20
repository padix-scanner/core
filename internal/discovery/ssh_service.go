
package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"core/pkg/models"
)

// discoverSSHService detects an SSH service on the target.
func discoverSSHService(target string) ([]models.Service, error) {
	const port = 22

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
		Name:       string(ServiceSSH),
		State:      "open",
		Confidence: "high",
	}

	// Read the SSH identification banner.
	if err := conn.SetReadDeadline(
		time.Now().Add(3 * time.Second),
	); err == nil {
		reader := bufio.NewReader(conn)

		banner, err := reader.ReadString('\n')
		if err == nil {
			banner = strings.TrimSpace(banner)

			if strings.HasPrefix(banner, "SSH-") {
				service.Product = banner
			}
		}
	}

	return []models.Service{service}, nil
}
