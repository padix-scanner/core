package models

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
