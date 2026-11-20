package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"core/pkg/models"
)

// discoverSMTPService detects SMTP services on the target.
func discoverSMTPService(target string) ([]models.Service, error) {
	var services []models.Service

	ports := []int{25, 587}

	for _, port := range ports {
		service, err := probeSMTP(target, port)
		if err != nil {
			continue
		}

		services = append(services, service)
	}

	return services, nil
}

// probeSMTP checks an SMTP port and reads its welcome banner.
func probeSMTP(target string, port int) (models.Service, error) {
	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout(
		"tcp",
		address,
		3*time.Second,
	)
	if err != nil {
		return models.Service{}, err
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceSMTP),
		State:      "open",
		Confidence: "high",
	}

	if err := conn.SetReadDeadline(
		time.Now().Add(3 * time.Second),
	); err != nil {
		return service, nil
	}

	reader := bufio.NewReader(conn)

	banner, err := reader.ReadString('\n')
	if err != nil {
		return service, nil
	}

	banner = strings.TrimSpace(banner)

	// SMTP greetings normally begin with a 220 response.
	if strings.HasPrefix(banner, "220 ") ||
		strings.HasPrefix(banner, "220-") {
		service.Product = banner
	}

	return service, nil
}
