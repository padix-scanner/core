package sensitive

import (
	"context"
	"time"

	"core/pkg/models"
)

// Adapter exposes the sensitive-file assessment through the checks registry.
type Adapter struct{}

func (Adapter) Name() string     { return "sensitive-files" }
func (Adapter) Category() string { return "sensitive-files" }

func (Adapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open"
}

func (Adapter) Assess(ctx context.Context, endpoint string, _ models.Service) ([]models.Finding, error) {
	cfg := DefaultConfig()
	cfg.Timeout = 5 * time.Second
	return Assess(ctx, endpoint, cfg)
}