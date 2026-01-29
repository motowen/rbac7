package graph

// Widget resolvers - separated from system resolvers for better organization

import (
	"context"
	"fmt"
	"time"

	model1 "system/internal/system/graph/model"
	"system/internal/system/model"
	"system/internal/system/repository"
)

// ============================================
// Library Widget Resolvers
// ============================================

// CreateLibraryWidget is the resolver for the createLibraryWidget field.
func (r *mutationResolver) CreateLibraryWidget(ctx context.Context, input model1.CreateLibraryWidgetInput) (*model.LibraryWidget, error) {
	// Convert GraphQL input to model
	widget := &model.LibraryWidget{
		Name:        input.Name,
		Version:     input.Version,
		Type:        input.Type,
		TypeVersion: input.TypeVersion,
		Status:      "draft",
		Schema:      input.Schema,
		UserConfig:  input.UserConfig,
	}

	if input.Status != nil {
		widget.Status = *input.Status
	}
	if input.Datasource != nil {
		widget.Datasource = convertDatasourceInputsToModel(input.Datasource)
	}
	if input.ThumbnailURL != nil {
		widget.ThumbnailURL = *input.ThumbnailURL
	}

	result, err := r.WidgetRepo.CreateLibraryWidget(ctx, widget)
	if err != nil {
		return nil, fmt.Errorf("failed to create library widget: %w", err)
	}

	return result, nil
}

// UpdateLibraryWidget is the resolver for the updateLibraryWidget field.
func (r *mutationResolver) UpdateLibraryWidget(ctx context.Context, input model1.UpdateLibraryWidgetInput) (*model.LibraryWidget, error) {
	update := &repository.LibraryWidgetUpdate{}

	if input.Name != nil {
		update.Name = input.Name
	}
	if input.Version != nil {
		update.Version = input.Version
	}
	if input.Type != nil {
		update.Type = input.Type
	}
	if input.TypeVersion != nil {
		update.TypeVersion = input.TypeVersion
	}
	if input.Schema != nil {
		update.Schema = input.Schema
	}
	if input.Datasource != nil {
		datasources := convertDatasourceInputsToModel(input.Datasource)
		update.Datasource = datasources
	}
	if input.Status != nil {
		update.Status = input.Status
	}
	if input.ThumbnailURL != nil {
		update.ThumbnailURL = input.ThumbnailURL
	}
	if input.UserConfig != nil {
		update.UserConfig = input.UserConfig
	}

	result, err := r.WidgetRepo.UpdateLibraryWidget(ctx, input.ID, update)
	if err != nil {
		return nil, fmt.Errorf("failed to update library widget: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	return result, nil
}

// DeleteLibraryWidget is the resolver for the deleteLibraryWidget field.
func (r *mutationResolver) DeleteLibraryWidget(ctx context.Context, id string) (bool, error) {
	err := r.WidgetRepo.DeleteLibraryWidget(ctx, id)
	if err != nil {
		return false, fmt.Errorf("failed to delete library widget: %w", err)
	}
	return true, nil
}

// LibraryWidgets is the resolver for the libraryWidgets field.
func (r *queryResolver) LibraryWidgets(ctx context.Context) ([]*model.LibraryWidget, error) {
	widgets, err := r.WidgetRepo.GetLibraryWidgets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get library widgets: %w", err)
	}
	return widgets, nil
}

// LibraryWidget is the resolver for the libraryWidget field.
func (r *queryResolver) LibraryWidget(ctx context.Context, id string) (*model.LibraryWidget, error) {
	widget, err := r.WidgetRepo.GetLibraryWidget(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get library widget: %w", err)
	}
	return widget, nil
}

// ============================================
// Dashboard Widget Resolvers
// ============================================

// CreateDashboardWidget is the resolver for the createDashboardWidget field.
func (r *mutationResolver) CreateDashboardWidget(ctx context.Context, input model1.CreateDashboardWidgetInput) (*model.DashboardWidget, error) {
	// Verify library widget exists
	libraryWidget, err := r.WidgetRepo.GetLibraryWidget(ctx, input.LibraryWidgetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get library widget: %w", err)
	}
	if libraryWidget == nil {
		return nil, fmt.Errorf("library widget not found: %s", input.LibraryWidgetID)
	}

	widget := &model.DashboardWidget{
		DashboardID:     input.DashboardID,
		LibraryWidgetID: input.LibraryWidgetID,
		Layout:          convertDashboardLayoutInputToModel(input.Layout),
	}

	result, err := r.WidgetRepo.CreateDashboardWidget(ctx, widget)
	if err != nil {
		return nil, fmt.Errorf("failed to create dashboard widget: %w", err)
	}

	return result, nil
}

// UpdateDashboardWidget is the resolver for the updateDashboardWidget field.
func (r *mutationResolver) UpdateDashboardWidget(ctx context.Context, input model1.UpdateDashboardWidgetInput) (*model.DashboardWidget, error) {
	if input.Layout == nil {
		return nil, fmt.Errorf("layout is required for update")
	}

	layout := convertDashboardLayoutInputToModel(input.Layout)
	result, err := r.WidgetRepo.UpdateDashboardWidget(ctx, input.ID, &layout)
	if err != nil {
		return nil, fmt.Errorf("failed to update dashboard widget: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("dashboard widget not found")
	}

	return result, nil
}

// DeleteDashboardWidget is the resolver for the deleteDashboardWidget field.
func (r *mutationResolver) DeleteDashboardWidget(ctx context.Context, id string) (bool, error) {
	err := r.WidgetRepo.DeleteDashboardWidget(ctx, id)
	if err != nil {
		return false, fmt.Errorf("failed to delete dashboard widget: %w", err)
	}
	return true, nil
}

// DashboardWidgets is the resolver for the dashboardWidgets field.
func (r *queryResolver) DashboardWidgets(ctx context.Context, dashboardID string) ([]*model.DashboardWidget, error) {
	widgets, err := r.WidgetRepo.GetDashboardWidgets(ctx, dashboardID)
	if err != nil {
		return nil, fmt.Errorf("failed to get dashboard widgets: %w", err)
	}
	return widgets, nil
}

// DashboardWidget is the resolver for the dashboardWidget field.
func (r *queryResolver) DashboardWidget(ctx context.Context, id string) (*model.DashboardWidget, error) {
	widget, err := r.WidgetRepo.GetDashboardWidget(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get dashboard widget: %w", err)
	}
	return widget, nil
}

// ============================================
// Field Resolvers
// ============================================

// CreatedAt resolves the createdAt field for DashboardWidget
func (r *dashboardWidgetResolver) CreatedAt(ctx context.Context, obj *model.DashboardWidget) (string, error) {
	return obj.CreatedAt.Format(time.RFC3339), nil
}

// UpdatedAt resolves the updatedAt field for DashboardWidget
func (r *dashboardWidgetResolver) UpdatedAt(ctx context.Context, obj *model.DashboardWidget) (string, error) {
	return obj.UpdatedAt.Format(time.RFC3339), nil
}

// CreatedAt resolves the createdAt field for LibraryWidget
func (r *libraryWidgetResolver) CreatedAt(ctx context.Context, obj *model.LibraryWidget) (string, error) {
	return obj.CreatedAt.Format(time.RFC3339), nil
}

// UpdatedAt resolves the updatedAt field for LibraryWidget
func (r *libraryWidgetResolver) UpdatedAt(ctx context.Context, obj *model.LibraryWidget) (string, error) {
	return obj.UpdatedAt.Format(time.RFC3339), nil
}

// PublishedAt resolves the publishedAt field for LibraryWidget
func (r *libraryWidgetResolver) PublishedAt(ctx context.Context, obj *model.LibraryWidget) (*string, error) {
	if obj.PublishedAt == nil {
		return nil, nil
	}
	result := obj.PublishedAt.Format(time.RFC3339)
	return &result, nil
}

// ============================================
// Conversion Helpers
// ============================================

func convertDatasourceInputsToModel(inputs []*model1.DatasourceInput) []model.Datasource {
	if inputs == nil {
		return nil
	}
	result := make([]model.Datasource, len(inputs))
	for i, input := range inputs {
		result[i] = model.Datasource{
			ID:     input.ID,
			Name:   input.Name,
			Type:   input.Type,
			Config: input.Config,
		}
		if input.Description != nil {
			result[i].Description = *input.Description
		}
	}
	return result
}

func convertDashboardLayoutInputToModel(input *model1.DashboardWidgetLayoutInput) model.DashboardWidgetLayout {
	return model.DashboardWidgetLayout{
		X: input.X,
		Y: input.Y,
		W: input.W,
		H: input.H,
	}
}
