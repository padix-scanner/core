// Package exposedservices reports discovered network services that commonly
// require restricted network exposure or additional hardening.
package exposedservices

import (
	"fmt"
	"strings"

	"core/pkg/models"
)

type policy struct {
	severity       string
	title          string
	description    string
	recommendation string
}

// policies deliberately focus on services whose exposure commonly creates a
// meaningful attack surface. An open port is not, by itself, proof of a
// vulnerability; findings are therefore marked as exposed rather than
// vulnerable.
var policies = map[string]policy{
	"ftp": {
		severity: "high", title: "FTP service exposed",
		description:    "An FTP service is reachable. Traditional FTP does not encrypt credentials or transferred data, allowing network observers to capture sensitive information.",
		recommendation: "Disable FTP where possible or replace it with SFTP/FTPS. Restrict access to trusted networks and require strong authentication.",
	},
	"telnet": {
		severity: "critical", title: "Telnet service exposed",
		description:    "A Telnet service is reachable. Telnet transmits authentication data and session contents without encryption.",
		recommendation: "Disable Telnet and use SSH. Restrict management access with firewall rules or a dedicated management network.",
	},
	"ssh": {
		severity: "medium", title: "SSH service exposed",
		description:    "An SSH management service is reachable from the scan vantage point. Publicly reachable management interfaces increase brute-force and credential-abuse risk.",
		recommendation: "Limit SSH to trusted source addresses or a VPN, disable password authentication where practical, and enforce key-based authentication and MFA.",
	},
	"smb": {
		severity: "critical", title: "SMB service exposed",
		description:    "An SMB file-sharing service is reachable. Exposed SMB increases the risk of unauthorized file access and exploitation of SMB vulnerabilities.",
		recommendation: "Block SMB at the perimeter, restrict it to trusted internal networks, disable obsolete SMB versions, and keep the server patched.",
	},
	"rdp": {
		severity: "high", title: "Remote Desktop service exposed",
		description:    "An RDP remote-administration service is reachable. Internet-facing RDP is a frequent target for password attacks and exploitation.",
		recommendation: "Do not expose RDP directly to the Internet. Require VPN or a zero-trust gateway, MFA, account lockout controls, and network-level authentication.",
	},
	"vnc": {
		severity: "high", title: "VNC service exposed",
		description:    "A VNC remote-desktop service is reachable. Depending on configuration, remote desktop traffic and authentication may be weakly protected.",
		recommendation: "Restrict VNC to a trusted management network or VPN, use strong authentication, and protect sessions with an encrypted tunnel.",
	},
	"redis": {
		severity: "critical", title: "Redis service exposed",
		description:    "A Redis data-store service is reachable. An accessible Redis instance may expose application data or administrative operations if authentication and network controls are insufficient.",
		recommendation: "Bind Redis to trusted interfaces, firewall the service, enable authentication/ACLs, and never expose it directly to untrusted networks.",
	},
	"mysql": {
		severity: "high", title: "MySQL database exposed",
		description:    "A MySQL database service is reachable. Directly reachable database services increase the risk of credential attacks and unauthorized data access.",
		recommendation: "Restrict database access to application hosts and trusted administrators, require TLS, use least-privilege accounts, and keep the database patched.",
	},
	"postgresql": {
		severity: "high", title: "PostgreSQL database exposed",
		description:    "A PostgreSQL database service is reachable. Directly reachable database services increase the risk of credential attacks and unauthorized data access.",
		recommendation: "Restrict database access with network rules and pg_hba.conf, require TLS, use least-privilege roles, and keep PostgreSQL patched.",
	},
	"microsoft sql server": {
		severity: "high", title: "Microsoft SQL Server exposed",
		description:    "A Microsoft SQL Server database service is reachable. Direct database exposure increases the risk of credential attacks and unauthorized data access.",
		recommendation: "Restrict access to application hosts and trusted administrators, enforce strong authentication and TLS, and keep SQL Server patched.",
	},
	"oracle database": {
		severity: "high", title: "Oracle database exposed",
		description:    "An Oracle database listener is reachable. Direct database exposure increases the risk of credential attacks and unauthorized data access.",
		recommendation: "Restrict listener access to trusted hosts, enforce strong authentication and encrypted connections, and keep Oracle components patched.",
	},
	"pop3": {
		severity: "high", title: "POP3 service exposed",
		description:    "A POP3 mail-retrieval service is reachable. Unencrypted POP3 can expose mailbox credentials and message contents.",
		recommendation: "Disable plaintext POP3 or require POP3S, and restrict mail access to trusted networks where possible.",
	},
	"imap": {
		severity: "medium", title: "IMAP service exposed",
		description:    "An IMAP mail-retrieval service is reachable. If TLS is not enforced, credentials and mailbox contents may be exposed.",
		recommendation: "Require TLS, disable plaintext authentication, enforce strong authentication, and restrict access where practical.",
	},
	"imaps": {
		severity: "low", title: "IMAPS service exposed",
		description:    "An encrypted IMAP mail-retrieval service is reachable. Confirm that access is intentional and authentication is appropriately protected.",
		recommendation: "Require strong authentication, keep the mail server patched, and restrict mailbox access where practical.",
	},
	"pop3s": {
		severity: "low", title: "POP3S service exposed",
		description:    "An encrypted POP3 mail-retrieval service is reachable. Confirm that access is intentional and authentication is appropriately protected.",
		recommendation: "Require strong authentication, keep the mail server patched, and restrict mailbox access where practical.",
	},
	"smtp": {
		severity: "medium", title: "SMTP service exposed",
		description:    "An SMTP service is reachable. Mail services should be reviewed for open-relay behavior, weak authentication, and unnecessary public access.",
		recommendation: "Disable open relay, require authentication for message submission, enforce TLS, and apply abuse/rate-limiting controls.",
	},
	"dns": {
		severity: "low", title: "DNS service exposed",
		description:    "A DNS service is reachable. Public DNS may be intentional, but recursion and zone-transfer permissions should be restricted.",
		recommendation: "Disable open recursion for untrusted clients, restrict zone transfers to authorized secondaries, and apply response-rate limiting.",
	},
	"http": {
		severity: "low", title: "HTTP service exposed",
		description:    "An HTTP web service is reachable. Confirm that the service is intended to be public and that sensitive content is not served over cleartext HTTP.",
		recommendation: "Redirect users to HTTPS, enable HSTS on HTTPS responses, and restrict administrative paths and sensitive endpoints.",
	},
}

// Assess returns one exposure finding for a discovered open service when its
// service type has a security policy.
func Assess(service models.Service) []models.Finding {
	if !strings.EqualFold(strings.TrimSpace(service.State), "open") {
		return nil
	}

	name := strings.ToLower(strings.TrimSpace(service.Name))
	p, ok := policies[name]
	if !ok {
		return nil
	}

	protocol := strings.ToUpper(strings.TrimSpace(service.Protocol))
	if protocol == "" {
		protocol = "TCP"
	}

	product := strings.TrimSpace(service.Product)
	if product == "" {
		product = "not identified"
	}

	return []models.Finding{{
		ID:          fmt.Sprintf("exposed-service-%s-%d", findingSlug(name), service.Port),
		Title:       p.title,
		Category:    "exposed-services",
		Severity:    p.severity,
		Status:      "exposed",
		Confidence:  confidence(service),
		Description: p.description + " " + p.recommendation,
		Evidence: fmt.Sprintf("Service: %s\nEndpoint: %s/%d\nState: %s\nProduct: %s",
			service.Name, protocol, service.Port, service.State, product),
	}}
}

func confidence(service models.Service) string {
	if strings.EqualFold(service.Confidence, "high") {
		return "high"
	}
	return "medium"
}

func findingSlug(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
