package exposedservices

import (
	"strings"
	"testing"

	"core/pkg/models"
)

func TestAssessReportsRiskyOpenServices(t *testing.T) {
	service := models.Service{
		Port: 6379, Protocol: "TCP", Name: "Redis", State: "open",
		Product: "Redis 7.x", Confidence: "high",
	}

	findings := Assess(service)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	f := findings[0]
	if f.Category != "exposed-services" || f.Severity != "critical" || f.Status != "exposed" {
		t.Fatalf("unexpected finding: %#v", f)
	}
	if !strings.Contains(f.Evidence, "Redis 7.x") || !strings.Contains(f.Description, "firewall") {
		t.Fatalf("expected product evidence and remediation, got %#v", f)
	}
}

func TestAssessIgnoresClosedService(t *testing.T) {
	findings := Assess(models.Service{Port: 22, Name: "SSH", State: "closed"})
	if len(findings) != 0 {
		t.Fatalf("closed service must not be reported: %#v", findings)
	}
}

func TestAssessIgnoresUnknownService(t *testing.T) {
	findings := Assess(models.Service{Port: 12345, Name: "custom-service", State: "open"})
	if len(findings) != 0 {
		t.Fatalf("unknown service must not be reported: %#v", findings)
	}
}

func TestAssessUsesMediumConfidenceWhenDiscoveryConfidenceMissing(t *testing.T) {
	findings := Assess(models.Service{Port: 21, Name: "FTP", State: "open"})
	if len(findings) != 1 || findings[0].Confidence != "medium" {
		t.Fatalf("expected medium-confidence FTP finding, got %#v", findings)
	}
}
