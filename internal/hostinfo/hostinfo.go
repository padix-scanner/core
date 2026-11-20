// Package hostinfo infers remote host properties, such as the operating
// system, from information collected during service discovery. Detection is
// passive: it only uses service banners and open ports that were already
// observed, so it does not require additional packets or privileges.
package hostinfo

import (
	"fmt"
	"strings"

	"core/pkg/models"
)

// evidence is a single signal that points at an operating system family.
type evidence struct {
	os      string
	version string
	weight  int
	source  string
}

// DetectOS infers the operating system of a remote host from discovered
// services. Empty fields are returned when no usable evidence is available.
func DetectOS(services []models.Service) models.Host {
	var votes []evidence

	for _, service := range services {
		votes = append(votes, serviceEvidence(service)...)
	}

	if len(votes) == 0 {
		return models.Host{}
	}

	type tally struct {
		weight        int
		version       string
		versionWeight int
		topSource     string
		topWeight     int
	}

	tallies := make(map[string]*tally)
	order := make([]string, 0, len(votes))

	for _, vote := range votes {
		current, ok := tallies[vote.os]
		if !ok {
			current = &tally{}
			tallies[vote.os] = current
			order = append(order, vote.os)
		}

		current.weight += vote.weight

		if vote.weight > current.topWeight {
			current.topWeight = vote.weight
			current.topSource = vote.source
		}

		if vote.version != "" && vote.weight > current.versionWeight {
			current.versionWeight = vote.weight
			current.version = vote.version
		}
	}

	winner := order[0]

	for _, osName := range order[1:] {
		if tallies[osName].weight > tallies[winner].weight {
			winner = osName
		}
	}

	result := tallies[winner]

	return models.Host{
		OS:           winner,
		OSVersion:    result.version,
		OSConfidence: confidence(result.weight),
	}
}

// serviceEvidence converts a discovered service into OS evidence.
func serviceEvidence(service models.Service) []evidence {
	if service.State != "" && service.State != "open" {
		return nil
	}

	banner := strings.ToLower(strings.TrimSpace(service.Product))

	var votes []evidence

	switch strings.ToUpper(service.Name) {
	case "SSH":
		votes = append(votes, sshEvidence(banner)...)
	case "FTP":
		votes = append(votes, ftpEvidence(banner)...)
	case "SMTP":
		votes = append(votes, smtpEvidence(banner)...)
	case "HTTP":
		votes = append(votes, httpEvidence(banner, service.Technologies)...)
	}

	votes = append(votes, portEvidence(service)...)

	return votes
}

func sshEvidence(banner string) []evidence {
	var votes []evidence

	add := func(osName, version string, weight int) {
		votes = append(votes, evidence{
			os:      osName,
			version: version,
			weight:  weight,
			source:  "SSH banner",
		})
	}

	switch {
	case strings.Contains(banner, "openssh_for_windows"):
		add("Windows", "", 6)
	case strings.Contains(banner, "ubuntu"):
		add("Linux", "Ubuntu", 6)
	case strings.Contains(banner, "raspbian"):
		add("Linux", "Raspbian", 6)
	case strings.Contains(banner, "debian"):
		add("Linux", "Debian", 6)
	case strings.Contains(banner, "centos"):
		add("Linux", "CentOS", 6)
	case strings.Contains(banner, "red hat"), strings.Contains(banner, "rhel"):
		add("Linux", "Red Hat Enterprise Linux", 6)
	case strings.Contains(banner, "fedora"):
		add("Linux", "Fedora", 6)
	case strings.Contains(banner, "amazon linux"), strings.Contains(banner, "amzn"):
		add("Linux", "Amazon Linux", 6)
	case strings.Contains(banner, "alpine"):
		add("Linux", "Alpine Linux", 6)
	case strings.Contains(banner, "suse"):
		add("Linux", "SUSE Linux", 6)
	case strings.Contains(banner, "synology"):
		add("Linux", "Synology DSM", 6)
	case strings.Contains(banner, "freebsd"):
		add("FreeBSD", "", 6)
	case strings.Contains(banner, "openbsd"):
		add("OpenBSD", "", 6)
	case strings.Contains(banner, "netbsd"):
		add("NetBSD", "", 6)
	case strings.Contains(banner, "cisco"):
		add("Cisco IOS", "", 5)
	}

	return votes
}

func ftpEvidence(banner string) []evidence {
	lower := strings.ToLower(banner)

	var votes []evidence

	add := func(osName, version string, weight int) {
		votes = append(votes, evidence{
			os:      osName,
			version: version,
			weight:  weight,
			source:  "FTP banner",
		})
	}

	switch {
	case strings.Contains(lower, "microsoft ftp"), strings.Contains(lower, "filezilla"):
		add("Windows", "", 5)
	case strings.Contains(lower, "vsftpd"):
		add("Linux", "", 4)
	case strings.Contains(lower, "proftpd"):
		add("Linux", "", 4)
	case strings.Contains(lower, "pure-ftpd"):
		add("Linux", "", 3)
	case strings.Contains(lower, "wu-ftpd"):
		add("Unix", "", 2)
	}

	return votes
}

func smtpEvidence(banner string) []evidence {
	if strings.Contains(banner, "microsoft") {
		return []evidence{{
			os:     "Windows",
			weight: 5,
			source: "SMTP banner",
		}}
	}

	return nil
}

func httpEvidence(server string, technologies []models.Technology) []evidence {
	var votes []evidence

	for _, tech := range technologies {
		category := strings.ToLower(tech.Category)

		switch {
		case strings.EqualFold(tech.Name, "Microsoft IIS"):
			votes = append(votes, evidence{
				os:      "Windows",
				version: tech.Version,
				weight:  6,
				source:  "HTTP Server header",
			})
		case strings.EqualFold(tech.Name, "ASP.NET"),
			strings.EqualFold(tech.Name, "ASP.NET MVC"),
			strings.EqualFold(tech.Name, "Blazor"):
			votes = append(votes, evidence{
				os:     "Windows",
				weight: 3,
				source: "HTTP " + tech.Name + " technology",
			})
		case category == "web-server" && strings.Contains(strings.ToLower(tech.Version), "win32"):
			votes = append(votes, evidence{
				os:     "Windows",
				weight: 4,
				source: "HTTP Server version",
			})
		}
	}

	if server != "" {
		switch {
		case strings.Contains(server, "microsoft-iis"),
			strings.Contains(server, "win32"),
			strings.Contains(server, "microsoft-httpapi"):
			votes = append(votes, evidence{
				os:     "Windows",
				weight: 6,
				source: "HTTP Server header",
			})
		case strings.Contains(server, "ubuntu"):
			votes = append(votes, evidence{
				os:      "Linux",
				version: "Ubuntu",
				weight:  5,
				source:  "HTTP Server header",
			})
		case strings.Contains(server, "debian"):
			votes = append(votes, evidence{
				os:      "Linux",
				version: "Debian",
				weight:  5,
				source:  "HTTP Server header",
			})
		}
	}

	return votes
}

// portEvidence adds weaker OS hints based on Windows-only management and
// database services.
func portEvidence(service models.Service) []evidence {
	switch service.Port {
	case 445, 3389, 1433:
		return []evidence{{
			os:     "Windows",
			weight: 2,
			source: fmt.Sprintf("port %d/tcp open", service.Port),
		}}
	}

	return nil
}

func confidence(weight int) string {
	switch {
	case weight >= 6:
		return "high"
	case weight >= 3:
		return "medium"
	default:
		return "low"
	}
}
