package xss

import (
	"context"
	"core/pkg/models"
)

// XssAdapter adapts the xss package to the Check interface.
type XssAdapter struct{}

func (XssAdapter) Name() string     { return "xss" }
func (XssAdapter) Category() string { return "xss" }
func (XssAdapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open"
}
func (XssAdapter) Assess(ctx context.Context, endpoint string) ([]models.Finding, error) {
	return Assess(ctx, endpoint, DefaultConfig())
}
