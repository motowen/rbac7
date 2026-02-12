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

	// If publishing from changed, save current version to history first
	if widget.Status == model.StatusChanged {
		if err := s.WidgetRepo.SaveToHistory(ctx, widgetID, callerID); err != nil {
			return nil, fmt.Errorf("failed to save history: %w", err)
		}

		// Merge draft_data to main fields
		if widget.DraftData != nil {
			mergeUpdate := &repository.LibraryWidgetUpdate{}
			if widget.DraftData.Name != "" {
				mergeUpdate.Name = &widget.DraftData.Name
			}
			if widget.DraftData.Version != "" {
				mergeUpdate.Version = &widget.DraftData.Version
			}
			if widget.DraftData.Schema != nil {
				mergeUpdate.Schema = widget.DraftData.Schema
			}
			if widget.DraftData.Datasource != nil {
				mergeUpdate.Datasource = widget.DraftData.Datasource
			}
			if widget.DraftData.ThumbnailURL != "" {
				mergeUpdate.ThumbnailURL = &widget.DraftData.ThumbnailURL
			}
			if widget.DraftData.DisplayMode != "" {
				mergeUpdate.DisplayMode = &widget.DraftData.DisplayMode
			}
			if widget.DraftData.Tags != nil {
				mergeUpdate.Tags = widget.DraftData.Tags
			}
			if widget.DraftData.UserConfig != nil {
				mergeUpdate.UserConfig = widget.DraftData.UserConfig
			}
			if _, err := s.WidgetRepo.UpdateLibraryWidget(ctx, widgetID, mergeUpdate); err != nil {
				return nil, fmt.Errorf("failed to merge draft data: %w", err)
			}
		}
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
