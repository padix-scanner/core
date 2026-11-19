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
	CVE        string `json:"cve"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
}

type ScanResult struct {
	Host     Host      `json:"host"`
	Packages []Package `json:"packages"`
	Findings []Finding `json:"findings"`
}
