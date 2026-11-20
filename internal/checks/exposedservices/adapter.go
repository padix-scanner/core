package exposedservices

import (
	"context"
	"core/pkg/models"
)

// Adapter adapts the package to the Check interface.
type Adapter struct{}

func (Adapter) Name() string     { return "exposed-services" }
func (Adapter) Category() string { return "exposed-services" }
func (Adapter) ShouldRun(s models.Service) bool {
	return true
}
func (Adapter) Assess(ctx context.Context, endpoint string, service models.Service) ([]models.Finding, error) {
	return Assess(service), nil
}