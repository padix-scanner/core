package dirlist

import (
	"context"

	"core/pkg/models"
)

// Adapter exposes directory-listing assessment through the checks registry.
type Adapter struct{}

func (Adapter) Name() string     { return "directory-listing" }
func (Adapter) Category() string { return "directory-listing" }

func (Adapter) ShouldRun(service models.Service) bool {
	return service.Name == "HTTP" && service.State == "open"
}

func (Adapter) Assess(ctx context.Context, endpoint string) ([]models.Finding, error) {
	return Assess(ctx, endpoint, DefaultConfig())
}
