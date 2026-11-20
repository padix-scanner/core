package models

type Host struct {
	Hostname     string `json:"hostname"`
	IP           string `json:"ip"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	OSConfidence string `json:"os_confidence,omitempty"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
}
