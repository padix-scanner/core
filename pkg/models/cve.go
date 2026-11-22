package models

import "time"

type CVEFinding struct {
	CVE        string  `json:"cve"`
	Package    string  `json:"package"`
	Version    string  `json:"version"`
	Severity   string  `json:"severity"`
	CVSS       float64 `json:"cvss"`
	Status     string  `json:"status"`
	Confidence string  `json:"confidence"`
	// TODO: Add CVSS version and vector.
	// TODO: Add description.
	// TODO: Add affected service name.
	// TODO: Add affected service port/protocol.
	// TODO: Add matched product and version.
	// TODO: Add version range.
	// TODO: Add evidence and match method.
	// TODO: Add references.
	// TODO: Add published/modified timestamps.
	// TODO: Add CWE identifiers.
}

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Ecosystem    string `json:"ecosystem"`
}

type CVE struct {
	ID          string
	Description string
	Published   *time.Time
	Modified    *time.Time

	CVSS     float64
	Severity string

	CWE        []string
	References []Reference
	Affected   []AffectedProduct

	Status string
	Source string

	RawJSON []byte
}

type Reference struct {
	URL  string
	Tags []string
}

type AffectedProduct struct {
	Vendor     string
	Product    string
	PackageURL string

	CPE         string
	VersionType string

	Versions []VersionRange
}

type VersionRange struct {
	Version         string
	LessThan        string
	LessThanOrEqual string
	Status          string
}
