package models

type Technology struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Category   string `json:"category"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
}
