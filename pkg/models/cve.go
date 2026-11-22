package models

import "time"

// CVEFinding is a CVE correlated with an observed service or technology.
type CVEFinding struct {
	CVE             string    `json:"cve"`
	Package         string    `json:"package,omitempty"`
	Version         string    `json:"version,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	CVSS            float64   `json:"cvss,omitempty"`
	CVSSVector      string    `json:"cvss_vector,omitempty"`
	CVSSVersion     string    `json:"cvss_version,omitempty"`
	Status          string    `json:"status"`
	Confidence      string    `json:"confidence"`
	Description     string    `json:"description,omitempty"`
	MatchedProduct  string    `json:"matched_product,omitempty"`
	AffectedRange   string    `json:"affected_range,omitempty"`
	MatchMethod     string    `json:"match_method,omitempty"`
	ServicePort     int       `json:"service_port,omitempty"`
	ServiceProtocol string    `json:"service_protocol,omitempty"`
	References      []string  `json:"references,omitempty"`
	CWEs            []string  `json:"cwes,omitempty"`
	Published       time.Time `json:"published,omitempty"`
	Modified        time.Time `json:"modified,omitempty"`
	Evidence        string    `json:"evidence,omitempty"`
}

// Package describes an installed package discovered on a host.
type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Ecosystem    string `json:"ecosystem"`
}
