package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}

	return strings.TrimSuffix(target, "/")
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if len(target) > 253 {
		return fmt.Errorf("target is too long")
	}

	if net.ParseIP(target) != nil {
		return nil
	}

	// Reject URL paths, query strings and fragments.
	if strings.ContainsAny(target, "/?#@") {
		return fmt.Errorf("enter an IP address or domain, not a URL path")
	}

	u, err := url.Parse("//" + target)
	if err != nil || u.Hostname() != target {
		return fmt.Errorf("invalid domain")
	}

	if len(target) == 0 {
		return fmt.Errorf("invalid domain")
	}

	labels := strings.Split(target, ".")

	if len(labels) < 2 {
		return fmt.Errorf("domain must contain a valid suffix")
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid domain label")
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain labels cannot start or end with hyphens")
		}

		for _, char := range label {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '-') {
				return fmt.Errorf("invalid character in domain")
			}
		}
	}

	return nil
}
func findFile(dir, filename string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() == filename {
			return filepath.Join(dir, entry.Name()), nil
		}
	}
	return "", fmt.Errorf("file %q not found in %q", filename, dir)
}
