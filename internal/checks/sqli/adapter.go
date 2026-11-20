package sqli

import (
	"context"
	"core/pkg/models"
)

// Adapter adapts the sqli package to the Check interface.
type Adapter struct{}

func (Adapter) Name() string     { return "sqli" }
func (Adapter) Category() string { return "sql-injection" }
func (Adapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open"
}
func (Adapter) Assess(ctx context.Context, endpoint string, service models.Service) ([]models.Finding, error) {
	return Assess(ctx, endpoint, DefaultConfig())
}
