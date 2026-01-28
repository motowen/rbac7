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
func (r *mutationResolver) CreateLibraryWidget(ctx context.Context, input model1.CreateLibraryWidgetInput) (*model1.LibraryWidget, error) {
	// Convert GraphQL input to model
	widget := &model.LibraryWidget{
		Type:     input.Type,
		Metadata: convertMetadataInputToModel(input.Metadata),
		Status:   string(model1.WidgetStatusDraft),
	}

	if input.Status != nil {
		widget.Status = string(*input.Status)
	}
	if input.Datasource != nil {
		widget.Datasource = convertDatasourceInputToModel(input.Datasource)
	}
	if input.Props != nil {
		widget.Props = convertPropsInputToModel(input.Props)
	}
	if input.Slots != nil {
		widget.Slots = convertSlotsInputToModel(input.Slots)
	}
	if input.Layout != nil {
		widget.Layout = convertLibraryLayoutInputToModel(input.Layout)
	}

	result, err := r.WidgetRepo.CreateLibraryWidget(ctx, widget)
	if err != nil {
		return nil, fmt.Errorf("failed to create library widget: %w", err)
	}

	return convertLibraryWidgetToGraphQL(result), nil
}

// UpdateLibraryWidget is the resolver for the updateLibraryWidget field.
func (r *mutationResolver) UpdateLibraryWidget(ctx context.Context, input model1.UpdateLibraryWidgetInput) (*model1.LibraryWidget, error) {
	update := &repository.LibraryWidgetUpdate{}

	if input.Type != nil {
		update.Type = input.Type
	}
	if input.Metadata != nil {
		metadata := convertMetadataInputToModel(input.Metadata)
		update.Metadata = &metadata
	}
	if input.Datasource != nil {
		update.Datasource = convertDatasourceInputToModel(input.Datasource)
	}
	if input.Props != nil {
		update.Props = convertPropsInputToModel(input.Props)
	}
	if input.Slots != nil {
		update.Slots = convertSlotsInputToModel(input.Slots)
	}
	if input.Layout != nil {
		layout := convertLibraryLayoutInputToModel(input.Layout)
		update.Layout = &layout
	}
	if input.Status != nil {
		status := string(*input.Status)
		update.Status = &status
	}

	result, err := r.WidgetRepo.UpdateLibraryWidget(ctx, input.ID, update)
	if err != nil {
		return nil, fmt.Errorf("failed to update library widget: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	return convertLibraryWidgetToGraphQL(result), nil
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
func (r *queryResolver) LibraryWidgets(ctx context.Context) ([]*model1.LibraryWidget, error) {
	widgets, err := r.WidgetRepo.GetLibraryWidgets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get library widgets: %w", err)
	}

	result := make([]*model1.LibraryWidget, len(widgets))
	for i, w := range widgets {
		result[i] = convertLibraryWidgetToGraphQL(w)
	}
	return result, nil
}

// LibraryWidget is the resolver for the libraryWidget field.
func (r *queryResolver) LibraryWidget(ctx context.Context, id string) (*model1.LibraryWidget, error) {
	widget, err := r.WidgetRepo.GetLibraryWidget(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get library widget: %w", err)
	}
	if widget == nil {
		return nil, nil
	}
	return convertLibraryWidgetToGraphQL(widget), nil
}

// ============================================
// Dashboard Widget Resolvers
// ============================================

// CreateDashboardWidget is the resolver for the createDashboardWidget field.
func (r *mutationResolver) CreateDashboardWidget(ctx context.Context, input model1.CreateDashboardWidgetInput) (*model1.DashboardWidget, error) {
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

	return convertDashboardWidgetToGraphQL(result, libraryWidget), nil
}

// UpdateDashboardWidget is the resolver for the updateDashboardWidget field.
func (r *mutationResolver) UpdateDashboardWidget(ctx context.Context, input model1.UpdateDashboardWidgetInput) (*model1.DashboardWidget, error) {
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

	// Get library widget for response
	libraryWidget, _ := r.WidgetRepo.GetLibraryWidget(ctx, result.LibraryWidgetID)

	return convertDashboardWidgetToGraphQL(result, libraryWidget), nil
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
func (r *queryResolver) DashboardWidgets(ctx context.Context, dashboardID string) ([]*model1.DashboardWidget, error) {
	widgets, err := r.WidgetRepo.GetDashboardWidgets(ctx, dashboardID)
	if err != nil {
		return nil, fmt.Errorf("failed to get dashboard widgets: %w", err)
	}

	result := make([]*model1.DashboardWidget, len(widgets))
	for i, w := range widgets {
		// Get library widget for each dashboard widget
		libraryWidget, _ := r.WidgetRepo.GetLibraryWidget(ctx, w.LibraryWidgetID)
		result[i] = convertDashboardWidgetToGraphQL(w, libraryWidget)
	}
	return result, nil
}

// DashboardWidget is the resolver for the dashboardWidget field.
func (r *queryResolver) DashboardWidget(ctx context.Context, id string) (*model1.DashboardWidget, error) {
	widget, err := r.WidgetRepo.GetDashboardWidget(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get dashboard widget: %w", err)
	}
	if widget == nil {
		return nil, nil
	}

	// Get library widget
	libraryWidget, _ := r.WidgetRepo.GetLibraryWidget(ctx, widget.LibraryWidgetID)

	return convertDashboardWidgetToGraphQL(widget, libraryWidget), nil
}

// ============================================
// Conversion Helpers
// ============================================

func convertMetadataInputToModel(input *model1.WidgetMetadataInput) model.WidgetMetadata {
	result := model.WidgetMetadata{
		Name: input.Name,
	}
	if input.Description != nil {
		result.Description = *input.Description
	}
	return result
}

func convertDatasourceInputToModel(input *model1.DatasourceInput) *model.Datasource {
	if input == nil {
		return nil
	}
	result := &model.Datasource{
		ID:           input.ID,
		Name:         input.Name,
		Type:         input.Type,
		Trigger:      string(input.Trigger),
		DatasourceID: input.DatasourceID,
	}
	if input.Transform != nil {
		result.Transform = *input.Transform
	}
	if input.ParamMap != nil {
		result.ParamMap = make([]model.ParamMap, len(input.ParamMap))
		for i, pm := range input.ParamMap {
			result.ParamMap[i] = model.ParamMap{Key: pm.Key, Value: pm.Value}
		}
	}
	return result
}

func convertPropsInputToModel(input *model1.WidgetPropsInput) *model.WidgetProps {
	if input == nil {
		return nil
	}
	result := &model.WidgetProps{}
	if input.Title != nil {
		result.Title = *input.Title
	}
	if input.Description != nil {
		result.Description = *input.Description
	}
	if input.Fields != nil {
		result.Fields = make([]model.FieldConfig, len(input.Fields))
		for i, f := range input.Fields {
			result.Fields[i] = model.FieldConfig{
				Key:   f.Key,
				Label: f.Label,
				Type:  string(f.Type),
			}
			if f.Width != nil {
				result.Fields[i].Width = *f.Width
			}
		}
	}
	if input.Options != nil {
		result.Options = &model.PropsOptions{}
		if input.Options.EnablePagination != nil {
			result.Options.EnablePagination = *input.Options.EnablePagination
		}
		if input.Options.PageSize != nil {
			result.Options.PageSize = *input.Options.PageSize
		}
		if input.Options.EnableSorting != nil {
			result.Options.EnableSorting = *input.Options.EnableSorting
		}
	}
	return result
}

func convertSlotsInputToModel(input *model1.SlotsConfigInput) *model.SlotsConfig {
	if input == nil {
		return nil
	}
	result := &model.SlotsConfig{}
	if input.Config != nil {
		result.Config = *input.Config
	}
	return result
}

func convertLibraryLayoutInputToModel(input *model1.LibraryWidgetLayoutInput) model.LibraryWidgetLayout {
	result := model.LibraryWidgetLayout{
		X: input.X,
		Y: input.Y,
		W: input.W,
		H: input.H,
	}
	if input.MinW != nil {
		result.MinW = *input.MinW
	}
	if input.MinH != nil {
		result.MinH = *input.MinH
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

func convertLibraryWidgetToGraphQL(w *model.LibraryWidget) *model1.LibraryWidget {
	result := &model1.LibraryWidget{
		ID:        w.ID,
		Type:      w.Type,
		Status:    model1.WidgetStatus(w.Status),
		CreatedAt: w.CreatedAt.Format(time.RFC3339),
		UpdatedAt: w.UpdatedAt.Format(time.RFC3339),
		Metadata: &model1.WidgetMetadata{
			Name:        w.Metadata.Name,
			Description: &w.Metadata.Description,
		},
		Layout: &model1.LibraryWidgetLayout{
			X:    w.Layout.X,
			Y:    w.Layout.Y,
			W:    w.Layout.W,
			H:    w.Layout.H,
			MinW: intPtrOrNil(w.Layout.MinW),
			MinH: intPtrOrNil(w.Layout.MinH),
		},
	}

	if w.Datasource != nil {
		result.Datasource = &model1.Datasource{
			ID:           w.Datasource.ID,
			Name:         w.Datasource.Name,
			Type:         w.Datasource.Type,
			Trigger:      model1.DatasourceTrigger(w.Datasource.Trigger),
			DatasourceID: w.Datasource.DatasourceID,
			Transform:    &w.Datasource.Transform,
		}
		if len(w.Datasource.ParamMap) > 0 {
			result.Datasource.ParamMap = make([]*model1.ParamMap, len(w.Datasource.ParamMap))
			for i, pm := range w.Datasource.ParamMap {
				result.Datasource.ParamMap[i] = &model1.ParamMap{Key: pm.Key, Value: pm.Value}
			}
		}
	}

	if w.Props != nil {
		result.Props = &model1.WidgetProps{
			Title:       &w.Props.Title,
			Description: &w.Props.Description,
		}
		if len(w.Props.Fields) > 0 {
			result.Props.Fields = make([]*model1.FieldConfig, len(w.Props.Fields))
			for i, f := range w.Props.Fields {
				result.Props.Fields[i] = &model1.FieldConfig{
					Key:   f.Key,
					Label: f.Label,
					Type:  model1.FieldType(f.Type),
					Width: intPtrOrNil(f.Width),
				}
			}
		}
		if w.Props.Options != nil {
			result.Props.Options = &model1.PropsOptions{
				EnablePagination: &w.Props.Options.EnablePagination,
				PageSize:         intPtrOrNil(w.Props.Options.PageSize),
				EnableSorting:    &w.Props.Options.EnableSorting,
			}
		}
	}

	if w.Slots != nil {
		result.Slots = &model1.SlotsConfig{
			Config: &w.Slots.Config,
		}
	}

	return result
}

func convertDashboardWidgetToGraphQL(w *model.DashboardWidget, libraryWidget *model.LibraryWidget) *model1.DashboardWidget {
	result := &model1.DashboardWidget{
		ID:              w.ID,
		DashboardID:     w.DashboardID,
		LibraryWidgetID: w.LibraryWidgetID,
		CreatedAt:       w.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       w.UpdatedAt.Format(time.RFC3339),
		Layout: &model1.DashboardWidgetLayout{
			X: w.Layout.X,
			Y: w.Layout.Y,
			W: w.Layout.W,
			H: w.Layout.H,
		},
	}

	if libraryWidget != nil {
		result.LibraryWidget = convertLibraryWidgetToGraphQL(libraryWidget)
	}

	return result
}

func intPtrOrNil(val int) *int {
	if val == 0 {
		return nil
	}
	return &val
}
