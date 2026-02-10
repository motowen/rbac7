package service

import (
	"context"
	"fmt"

	"system/internal/system/model"
	"system/internal/system/repository"
)

// WidgetService handles library widget business logic
type WidgetService struct {
	Entity     *EntityService
	WidgetRepo repository.WidgetRepository
}

// NewWidgetService creates a new WidgetService
func NewWidgetService(entity *EntityService, widgetRepo repository.WidgetRepository) *WidgetService {
	return &WidgetService{
		Entity:     entity,
		WidgetRepo: widgetRepo,
	}
}

// Update updates a library widget (requires editable status + not locked)
func (s *WidgetService) Update(ctx context.Context, callerID, widgetID string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	if err := s.Entity.EnsureEditable(ctx, model.EntityTypeLibraryWidget, widgetID, callerID, widget.Status); err != nil {
		return nil, err
	}

	result, err := s.WidgetRepo.UpdateLibraryWidget(ctx, widgetID, update)
	if err != nil {
		return nil, fmt.Errorf("failed to update library widget: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("library widget not found")
	}
	return result, nil
}

// Publish transitions library widget from draft/changed → published
func (s *WidgetService) Publish(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	if err := model.ValidateStatusTransition(widget.Status, model.StatusPublished); err != nil {
		return nil, err
	}

	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, model.StatusPublished, "")
}

// Change transitions library widget from published → changed
func (s *WidgetService) Change(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	if err := model.ValidateStatusTransition(widget.Status, model.StatusChanged); err != nil {
		return nil, err
	}

	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, model.StatusChanged, model.StatusPublished)
}

// Trash transitions library widget to trashed (soft delete)
func (s *WidgetService) Trash(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	if err := model.ValidateStatusTransition(widget.Status, model.StatusTrashed); err != nil {
		return nil, err
	}

	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, model.StatusTrashed, widget.Status)
}

// Restore transitions library widget from trashed → previous status
func (s *WidgetService) Restore(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	if widget.Status != model.StatusTrashed {
		return nil, fmt.Errorf("can only restore trashed widget")
	}

	previousStatus := widget.PreviousStatus
	if previousStatus == "" {
		previousStatus = model.StatusDraft
	}

	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, previousStatus, "")
}
