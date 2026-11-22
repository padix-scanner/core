package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"core/pkg/models"
)

// discoverRedisService detects a Redis service on the target (port 6379).
// It performs a TCP connect and optionally reads an unauthenticated PING response.
func discoverRedisService(target string) ([]models.Service, error) {
	const port = 6379

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceRedis),
		State:      "open",
		Confidence: "high",
	}

	// Best-effort probe: send PING and look for a Redis-style response.
	// Many Redis instances reply +PONG; others may return an auth error.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err == nil {
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err == nil {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)
			if strings.HasPrefix(line, "+PONG") ||
				strings.Contains(lower, "redis") ||
				strings.Contains(lower, "noauth") ||
				strings.Contains(lower, "auth") ||
				strings.HasPrefix(line, "-ERR") {
				service.Product = line
			}
		}
	}

	return []models.Service{service}, nil
}
