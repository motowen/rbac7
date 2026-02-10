package service

import (
	"context"
	"fmt"

	"system/internal/system/model"
	"system/internal/system/repository"
)

// DashboardService handles dashboard business logic
type DashboardService struct {
	Entity        *EntityService
	DashboardRepo repository.DashboardRepository
	WidgetRepo    repository.WidgetRepository
}

// NewDashboardService creates a new DashboardService
func NewDashboardService(entity *EntityService, dashboardRepo repository.DashboardRepository, widgetRepo repository.WidgetRepository) *DashboardService {
	return &DashboardService{
		Entity:        entity,
		DashboardRepo: dashboardRepo,
		WidgetRepo:    widgetRepo,
	}
}

// Update updates dashboard info (requires draft or changed status + not locked by other)
func (s *DashboardService) Update(ctx context.Context, callerID, dashboardID string, update *repository.DashboardUpdate) (*model.Dashboard, error) {
	dashboard, err := s.DashboardRepo.GetDashboard(ctx, dashboardID)
	if err != nil {
		return nil, err
	}
	if dashboard == nil {
		return nil, repository.ErrDashboardNotFound
	}

	if err := s.Entity.EnsureEditable(ctx, model.EntityTypeDashboard, dashboardID, callerID, dashboard.Status); err != nil {
		return nil, err
	}

	return s.DashboardRepo.UpdateDashboard(ctx, dashboardID, update)
}

// Publish transitions dashboard from draft/changed → published
func (s *DashboardService) Publish(ctx context.Context, callerID, dashboardID string) (*model.Dashboard, error) {
	dashboard, err := s.DashboardRepo.GetDashboard(ctx, dashboardID)
	if err != nil {
		return nil, err
	}
	if dashboard == nil {
		return nil, repository.ErrDashboardNotFound
	}

	if err := model.ValidateStatusTransition(dashboard.Status, model.StatusPublished); err != nil {
		return nil, err
	}

	// If publishing from changed, save to history first
	if dashboard.Status == model.StatusChanged {
		if err := s.DashboardRepo.SaveToHistory(ctx, dashboardID, callerID); err != nil {
			return nil, fmt.Errorf("failed to save history: %w", err)
		}
		// Delete old published widgets
		if err := s.DashboardRepo.DeleteWidgetsByVersion(ctx, dashboardID, "published"); err != nil {
			return nil, fmt.Errorf("failed to delete old widgets: %w", err)
		}
		// Promote draft widgets to published
		if err := s.DashboardRepo.PromoteDraftToPublished(ctx, dashboardID); err != nil {
			return nil, fmt.Errorf("failed to promote widgets: %w", err)
		}
		// Merge draft_data to main fields
		if dashboard.DraftData != nil {
			mergeUpdate := &repository.DashboardUpdate{}
			if dashboard.DraftData.Name != "" {
				mergeUpdate.Name = &dashboard.DraftData.Name
			}
			if dashboard.DraftData.Description != "" {
				mergeUpdate.Description = &dashboard.DraftData.Description
			}
			if _, err := s.DashboardRepo.UpdateDashboard(ctx, dashboardID, mergeUpdate); err != nil {
				return nil, err
			}
		}
	} else {
		// Publishing from draft - promote draft widgets to published
		if err := s.DashboardRepo.PromoteDraftToPublished(ctx, dashboardID); err != nil {
			return nil, fmt.Errorf("failed to promote widgets: %w", err)
		}
	}

	return s.DashboardRepo.UpdateDashboardStatus(ctx, dashboardID, model.StatusPublished, "")
}

// Change transitions dashboard from published → changed, copies widgets to draft
func (s *DashboardService) Change(ctx context.Context, callerID, dashboardID string) (*model.Dashboard, error) {
	dashboard, err := s.DashboardRepo.GetDashboard(ctx, dashboardID)
	if err != nil {
		return nil, err
	}
	if dashboard == nil {
		return nil, repository.ErrDashboardNotFound
	}

	if err := model.ValidateStatusTransition(dashboard.Status, model.StatusChanged); err != nil {
		return nil, err
	}

	// Copy published widgets to draft
	if err := s.DashboardRepo.CopyWidgetsToDraft(ctx, dashboardID); err != nil {
		return nil, fmt.Errorf("failed to copy widgets: %w", err)
	}

	return s.DashboardRepo.UpdateDashboardStatus(ctx, dashboardID, model.StatusChanged, model.StatusPublished)
}

// Delete transitions dashboard to trashed
func (s *DashboardService) Delete(ctx context.Context, callerID, dashboardID string) (*model.Dashboard, error) {
	dashboard, err := s.DashboardRepo.GetDashboard(ctx, dashboardID)
	if err != nil {
		return nil, err
	}
	if dashboard == nil {
		return nil, repository.ErrDashboardNotFound
	}

	if err := model.ValidateStatusTransition(dashboard.Status, model.StatusTrashed); err != nil {
		return nil, err
	}

	return s.DashboardRepo.UpdateDashboardStatus(ctx, dashboardID, model.StatusTrashed, dashboard.Status)
}

// Restore transitions dashboard from trashed → previous status
func (s *DashboardService) Restore(ctx context.Context, callerID, dashboardID string) (*model.Dashboard, error) {
	dashboard, err := s.DashboardRepo.GetDashboard(ctx, dashboardID)
	if err != nil {
		return nil, err
	}
	if dashboard == nil {
		return nil, repository.ErrDashboardNotFound
	}

	if dashboard.Status != model.StatusTrashed {
		return nil, fmt.Errorf("can only restore trashed dashboard")
	}

	previousStatus := dashboard.PreviousStatus
	if previousStatus == "" {
		previousStatus = model.StatusDraft
	}

	return s.DashboardRepo.UpdateDashboardStatus(ctx, dashboardID, previousStatus, "")
}

// AddWidget adds a widget to dashboard (requires editable status + not locked)
func (s *DashboardService) AddWidget(ctx context.Context, callerID string, dashboard *model.Dashboard, widget *model.DashboardWidget) (*model.DashboardWidget, error) {
	if err := s.Entity.EnsureEditable(ctx, model.EntityTypeDashboard, dashboard.ID, callerID, dashboard.Status); err != nil {
		return nil, err
	}

	return s.DashboardRepo.AddWidgetToDashboard(ctx, widget)
}

// UpdateWidget updates a dashboard widget (requires editable status + draft version + not locked)
func (s *DashboardService) UpdateWidget(ctx context.Context, callerID string, widgetID string, update *repository.DashboardWidgetUpdate) (*model.DashboardWidget, error) {
	widget, err := s.DashboardRepo.GetDashboardWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, repository.ErrWidgetNotFound
	}

	// Check dashboard status
	dashboard, err := s.DashboardRepo.GetDashboard(ctx, widget.DashboardID)
	if err != nil {
		return nil, err
	}
	if dashboard == nil {
		return nil, repository.ErrDashboardNotFound
	}

	if err := s.Entity.EnsureEditable(ctx, model.EntityTypeDashboard, dashboard.ID, callerID, dashboard.Status); err != nil {
		return nil, err
	}

	if widget.Version != "draft" {
		return nil, fmt.Errorf("can only update draft version widget")
	}

	return s.DashboardRepo.UpdateDashboardWidget(ctx, widgetID, update)
}

// RemoveWidget removes a dashboard widget (requires editable status + draft version + not locked)
func (s *DashboardService) RemoveWidget(ctx context.Context, callerID string, widgetID string) error {
	widget, err := s.DashboardRepo.GetDashboardWidget(ctx, widgetID)
	if err != nil {
		return err
	}
	if widget == nil {
		return repository.ErrWidgetNotFound
	}

	dashboard, err := s.DashboardRepo.GetDashboard(ctx, widget.DashboardID)
	if err != nil {
		return err
	}
	if dashboard == nil {
		return repository.ErrDashboardNotFound
	}

	if err := s.Entity.EnsureEditable(ctx, model.EntityTypeDashboard, dashboard.ID, callerID, dashboard.Status); err != nil {
		return err
	}

	if widget.Version != "draft" {
		return fmt.Errorf("can only remove draft version widget")
	}

	return s.DashboardRepo.RemoveDashboardWidget(ctx, widgetID)
}
