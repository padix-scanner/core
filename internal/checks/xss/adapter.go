package xss

import (
	"context"
	"core/pkg/models"
)

// Adapter adapts the xss package to the Check interface.
type Adapter struct{}

func (Adapter) Name() string     { return "xss" }
func (Adapter) Category() string { return "xss" }
func (Adapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open"
}
func (Adapter) Assess(ctx context.Context, endpoint string, service models.Service) ([]models.Finding, error) {
	return Assess(ctx, endpoint, DefaultConfig())
}
