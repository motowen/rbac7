package graph

import (
	"system/internal/system/client"
	"system/internal/system/repository"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	Repo       repository.SystemRepository
	WidgetRepo repository.WidgetRepository
	RBACClient *client.RBACClient
}

// DashboardWidget returns DashboardWidgetResolver implementation.
func (r *Resolver) DashboardWidget() DashboardWidgetResolver { return &dashboardWidgetResolver{r} }

// Datasource returns DatasourceResolver implementation.
func (r *Resolver) Datasource() DatasourceResolver { return &datasourceResolver{r} }

// LibraryWidget returns LibraryWidgetResolver implementation.
func (r *Resolver) LibraryWidget() LibraryWidgetResolver { return &libraryWidgetResolver{r} }

type dashboardWidgetResolver struct{ *Resolver }
type datasourceResolver struct{ *Resolver }
type libraryWidgetResolver struct{ *Resolver }
