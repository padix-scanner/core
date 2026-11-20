package sqli

import (
	"context"
	"core/pkg/models"
)

// SqliAdapter adapts the sqli package to the Check interface.
type SqliAdapter struct{}

func (SqliAdapter) Name() string     { return "sqli" }
func (SqliAdapter) Category() string { return "sql-injection" }
func (SqliAdapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open"
}
func (SqliAdapter) Assess(ctx context.Context, endpoint string) ([]models.Finding, error) {
	return Assess(ctx, endpoint, DefaultConfig())
}
