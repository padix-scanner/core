package sqli

import (
	"context"
	"core/pkg/models"
	"time"
)

type Adapter struct{}

func (Adapter) Name() string {
	return "sqli"
}

func (Adapter) Category() string {
	return "sql-injection"
}

func (Adapter) ShouldRun(s models.Service) bool {
	return s.Name == "HTTP" && s.State == "open"
}

func (Adapter) Assess(
	ctx context.Context,
	endpoint string,
	service models.Service,
) ([]models.Finding, error) {
	cfg := DefaultConfig()

	cfg.Timeout = 4 * time.Second
	cfg.MaxPages = 8
	cfg.MaxParameters = 4

	return Assess(ctx, endpoint, cfg)
}
