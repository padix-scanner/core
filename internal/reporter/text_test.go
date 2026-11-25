package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"core/pkg/models"
)

func sampleResult() models.ScanResult {
	return models.ScanResult{
		Host: models.Host{
			Hostname:     "web01",
			OS:           "Linux",
			OSVersion:    "22.04",
			OSConfidence: "high",
			Kernel:       "5.15.0",
			Architecture: "x86_64",
		},
		Services: []models.Service{
			{
				Port:     80,
				Protocol: "tcp",
				Name:     "http",
				State:    "open",
				Product:  "nginx",
				Technologies: []models.Technology{
					{Name: "nginx", Version: "1.18", Category: "web", Confidence: "high", Source: "banner"},
				},
			},
		},
		Technologies: []models.Technology{
			{Name: "openssl", Version: "", Category: "crypto", Confidence: "medium", Source: "port"},
		},
		Findings: []models.Finding{
			{
				ID:          "exposed-service-http-80",
				Title:       "Exposed HTTP service",
				Category:    "exposed-services",
				Severity:    "low",
				Status:      "open",
				Confidence:  "high",
				Description: "HTTP exposed",
				Evidence:    "Service: http\nState: open",
			},
			{
				ID:          "exposed-service-http-8080",
				Title:       "Exposed HTTP service",
				Category:    "exposed-services",
				Severity:    "low",
				Status:      "open",
				Confidence:  "high",
				Description: "HTTP exposed",
				Evidence:    "Service: http\nState: open",
			},
		},
		CVEs: []models.CVEFinding{
			{CVE: "CVE-2021-1234", Package: "nginx", Version: "1.18", Severity: "high", CVSS: 7.5, Status: "confirmed"},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}

	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("expected trailing newline")
	}

	var decoded models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Host.Hostname != "web01" {
		t.Errorf("hostname = %q, want web01", decoded.Host.Hostname)
	}
	if len(decoded.CVEs) != 1 {
		t.Errorf("cves = %d, want 1", len(decoded.CVEs))
	}
}

func TestWriteJSONNilWriter(t *testing.T) {
	if err := WriteJSON(nil, models.ScanResult{}); err == nil {
		t.Fatal("expected error for nil writer")
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"PADIX SECURITY REPORT",
		"[ HOST INFORMATION ]",
		"Hostname:     web01",
		"[ DISCOVERED SERVICES ]",
		"nginx",
		"[ TECHNOLOGY FINGERPRINTING ]",
		"[ VULNERABILITY ASSESSMENT ]",
		"Exposed HTTP service",
		"[ CVE CORRELATION ]",
		"CVE-2021-1234",
		"[ SCAN SUMMARY ]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestWriteTextMergesExposedServices(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	// The two exposed-service findings (ports 80 and 8080) merge into one.
	if got := strings.Count(buf.String(), "Exposed HTTP service"); got != 1 {
		t.Errorf("merged finding count = %d, want 1", got)
	}
}

func TestWriteTextNilWriter(t *testing.T) {
	if err := WriteText(nil, models.ScanResult{}); err == nil {
		t.Fatal("expected error for nil writer")
	}
}

func TestWriteTextEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, models.ScanResult{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"No services discovered.",
		"No technologies identified.",
		"No vulnerability findings available.",
		"No CVE findings available.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("empty report missing %q", want)
		}
	}
}

func TestValueOrNA(t *testing.T) {
	cases := map[string]string{
		"":       "N/A",
		"   ":    "N/A",
		"value":  "value",
		" nginx": " nginx",
	}
	for in, want := range cases {
		if got := valueOrNA(in); got != want {
			t.Errorf("valueOrNA(%q) = %q, want %q", in, got, want)
		}
	}
}