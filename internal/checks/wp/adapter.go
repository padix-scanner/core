package wp

import (
	"context"
	"time"

	"core/pkg/models"
)

// Adapter exposes the WordPress assessment through the checks registry.
type Adapter struct{}

func (Adapter) Name() string     { return "wordpress" }
func (Adapter) Category() string { return "wordpress" }

func (Adapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open"
}

func (Adapter) Assess(ctx context.Context, endpoint string, service models.Service) ([]models.Finding, error) {
	cfg := DefaultConfig()
	cfg.Timeout = 8 * time.Second
	return Assess(ctx, endpoint, cfg)
}
