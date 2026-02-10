package graph

import (
	"system/internal/system/repository"
	"system/internal/system/service"

	"system/internal/system/client"
)

// Resolver serves as dependency injection container for GraphQL resolvers
type Resolver struct {
	Repo             repository.SystemRepository
	WidgetRepo       repository.WidgetRepository
	DashboardRepo    repository.DashboardRepository
	LockRepo         repository.LockRepository
	RBACClient       *client.RBACClient
	EntityService    *service.EntityService
	DashboardService *service.DashboardService
	WidgetService    *service.WidgetService
}
