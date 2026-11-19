package models

type ScanResult struct {
	Host         Host         `json:"host"`
	Services     []Service    `json:"services"`
	Technologies []Technology `json:"technologies"`
	Findings     []Finding    `json:"findings"`
	CVEs         []CVEFinding `json:"cves"`
}
