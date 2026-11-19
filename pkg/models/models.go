package models

type Host struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
}

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Ecosystem    string `json:"ecosystem"`
}

type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

type Technology struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Category   string `json:"category"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
}

type CVEFinding struct {
	CVE        string  `json:"cve"`
	Package    string  `json:"package"`
	Version    string  `json:"version"`
	Severity   string  `json:"severity"`
	CVSS       float64 `json:"cvss"`
	Status     string  `json:"status"`
	Confidence string  `json:"confidence"`
}

type Target struct {
	Input    string `json:"input"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type ScanResult struct {
	Host         Host         `json:"host"`
	Technologies []Technology `json:"technologies"`
	Findings     []Finding    `json:"findings"`
	CVEs         []CVEFinding `json:"cves"`
}
