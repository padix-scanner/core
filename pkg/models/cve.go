package models

type CVEFinding struct {
	CVE        string  `json:"cve"`
	Package    string  `json:"package"`
	Version    string  `json:"version"`
	Severity   string  `json:"severity"`
	CVSS       float64 `json:"cvss"`
	Status     string  `json:"status"`
	Confidence string  `json:"confidence"`
}

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Ecosystem    string `json:"ecosystem"`
}