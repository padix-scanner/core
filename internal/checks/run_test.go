package checks

import (
	"context"
	"testing"

	"core/pkg/models"
)

func TestBuildEndpoint(t *testing.T) {
	cases := []struct {
		target  string
		service models.Service
		want    string
	}{
		{"example.com", models.Service{Port: 80}, "http://example.com:80/"},
		{"example.com", models.Service{Port: 443}, "https://example.com:443/"},
		{"example.com", models.Service{Port: 8443}, "https://example.com:8443/"},
	}
	for _, c := range cases {
		got := buildEndpoint(c.target, c.service)
		if got != c.want {
			t.Errorf("buildEndpoint(%s,%d) = %s want %s", c.target, c.service.Port, got, c.want)
		}
	}
}

func TestCheckTimeout(t *testing.T) {
	if checkTimeout("sqli") != 45*1e9 {
		t.Fatal("wrong")
	}
	if checkTimeout("unknown") != 2*60*1e9 {
		t.Fatal("wrong")
	}
}

func TestExecutePanicRecovery(t *testing.T) {
	// Use a fake check that panics
	chk := panicCheck{}
	findings, err := execute(context.Background(), chk, "http://x/", models.Service{})
	if err == nil {
		t.Fatal("expected err")
	}
	if findings != nil {
		t.Fatal("expected nil findings")
	}
}

type panicCheck struct{}

func (panicCheck) Name() string     { return "panic" }
func (panicCheck) Category() string { return "panic" }
func (panicCheck) ShouldRun(models.Service) bool { return true }
func (panicCheck) Assess(context.Context, string, models.Service) ([]models.Finding, error) {
	panic("boom")
}

func TestRunEmpty(t *testing.T) {
	findings, err := Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0, got %d", len(findings))
	}
}
