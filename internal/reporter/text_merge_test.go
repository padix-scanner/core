package reporter

import (
	"strings"
	"testing"

	"core/pkg/models"
)

func TestExposedGroupID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"exposed-service-http-80", "exposed-service-http"},
		{"exposed-service-https-443", "exposed-service-https"},
		{"no-port-suffix", "no-port-suffix"},
		{"trailing-dash-", "trailing-dash-"},
	}
	for _, c := range cases {
		got := exposedGroupID(models.Finding{ID: c.in})
		if got != c.want {
			t.Errorf("exposedGroupID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMergeEvidence(t *testing.T) {
	if got := mergeEvidence("", "a"); got != "a" {
		t.Errorf("empty existing = %q, want a", got)
	}
	if got := mergeEvidence("a", "a"); got != "a" {
		t.Errorf("duplicate = %q, want a", got)
	}
	if got := mergeEvidence("a", "b"); got != "a\n\nb" {
		t.Errorf("append = %q, want a\\n\\nb", got)
	}
}

func TestMergeExposedServices(t *testing.T) {
	findings := []models.Finding{
		{ID: "exposed-service-http-80", Category: "exposed-services", Title: "Exposed HTTP", Severity: "low", Status: "open", Evidence: "Service: http\nState: open"},
		{ID: "exposed-service-http-8080", Category: "exposed-services", Title: "Exposed HTTP", Severity: "low", Status: "open", Evidence: "Service: http\nState: open"},
		{ID: "other-1", Category: "sqli", Title: "SQLi", Severity: "high", Status: "open"},
	}

	out := mergeExposedServices(findings)
	if len(out) != 2 {
		t.Fatalf("merged length = %d, want 2", len(out))
	}
	if out[0].ID != "exposed-service-http" {
		t.Errorf("merged ID = %q, want exposed-service-http", out[0].ID)
	}
	if out[0].Evidence != "Service: http\nState: open" {
		t.Errorf("deduped evidence = %q", out[0].Evidence)
	}
	if out[1].ID != "other-1" {
		t.Errorf("second ID = %q, want other-1", out[1].ID)
	}
}

func TestMergeExposedServicesDistinctEvidence(t *testing.T) {
	findings := []models.Finding{
		{ID: "exposed-service-http-80", Category: "exposed-services", Title: "Exposed HTTP", Severity: "low", Status: "open", Evidence: "port 80"},
		{ID: "exposed-service-http-8080", Category: "exposed-services", Title: "Exposed HTTP", Severity: "low", Status: "open", Evidence: "port 8080"},
	}
	out := mergeExposedServices(findings)
	if len(out) != 1 {
		t.Fatalf("merged length = %d, want 1", len(out))
	}
	if !strings.Contains(out[0].Evidence, "port 80") || !strings.Contains(out[0].Evidence, "port 8080") {
		t.Errorf("evidence not merged: %q", out[0].Evidence)
	}
}