package models

type Service struct {
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Product    string `json:"product,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLSSubject string `json:"tls_subject,omitempty"`
	TLSExpiry  string `json:"tls_expiry,omitempty"`
	Confidence string `json:"confidence"`
}
