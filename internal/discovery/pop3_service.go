package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"core/pkg/models"
)

// discoverPOP3Service detects a POP3 service on the target (port 110).
func discoverPOP3Service(target string) ([]models.Service, error) {
	const port = 110

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServicePOP3),
		State:      "open",
		Confidence: "high",
	}

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return []models.Service{service}, nil
	}

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err == nil {
		banner = strings.TrimSpace(banner)
		// POP3 greetings normally begin with +OK.
		if strings.HasPrefix(banner, "+OK") {
			service.Product = banner
		}
	}

	return []models.Service{service}, nil
}
