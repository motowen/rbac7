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

// Update updates a library widget.
// - draft: update directly
// - published: copy to changed first, then update the changed copy
// - changed: update the changed copy directly
func (s *WidgetService) Update(ctx context.Context, callerID, widgetID string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	groupID := widget.GroupID
	if groupID == "" {
		groupID = widget.ID
	}

	switch widget.Status {
	case model.StatusDraft:
		// Draft: update directly
		if err := s.Entity.EnsureEditable(ctx, model.EntityTypeLibraryWidget, widgetID, callerID, widget.Status); err != nil {
			return nil, err
		}
		return s.WidgetRepo.UpdateLibraryWidget(ctx, widgetID, update)

	case model.StatusPublished:
		// Published: check if changed version already exists
		changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
		if err != nil {
			return nil, err
		}
		if changed != nil {
			// Changed version exists, update it
			if err := s.Entity.EnsureEditable(ctx, model.EntityTypeLibraryWidget, widgetID, callerID, model.StatusChanged); err != nil {
				return nil, err
			}
			return s.WidgetRepo.UpdateLibraryWidget(ctx, changed.ID, update)
		}
		// No changed version, create one from published
		changed, err = s.WidgetRepo.CopyToChanged(ctx, groupID)
		if err != nil {
			return nil, fmt.Errorf("failed to create changed copy: %w", err)
		}
		// Apply update to the changed copy
		result, err := s.WidgetRepo.UpdateLibraryWidget(ctx, changed.ID, update)
		if err != nil {
			return nil, fmt.Errorf("failed to update changed copy: %w", err)
		}
		return result, nil

	case model.StatusChanged:
		// Changed: update directly
		if err := s.Entity.EnsureEditable(ctx, model.EntityTypeLibraryWidget, widgetID, callerID, widget.Status); err != nil {
			return nil, err
		}
		return s.WidgetRepo.UpdateLibraryWidget(ctx, widgetID, update)

	default:
		return nil, fmt.Errorf("cannot update widget in %s status", widget.Status)
	}
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

	groupID := widget.GroupID
	if groupID == "" {
		groupID = widget.ID
	}

	if widget.Status == model.StatusDraft {
		// Publishing from draft: just change status
		if err := model.ValidateStatusTransition(widget.Status, model.StatusPublished); err != nil {
			return nil, err
		}
		return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, model.StatusPublished, "")
	}

	// Publishing from changed: need to find the changed version
	changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
	if err != nil {
		return nil, err
	}

	// If the widget itself is the changed version, use it
	if widget.Status == model.StatusChanged {
		changed = widget
	}

	if changed == nil {
		return nil, fmt.Errorf("no changed version found to publish")
	}

	if err := model.ValidateStatusTransition(changed.Status, model.StatusPublished); err != nil {
		return nil, err
	}

	// Save current published version to history
	if err := s.WidgetRepo.SaveToHistory(ctx, groupID, callerID); err != nil {
		return nil, fmt.Errorf("failed to save history: %w", err)
	}

	// Delete published version
	if err := s.WidgetRepo.DeleteByGroupAndStatus(ctx, groupID, model.StatusPublished); err != nil {
		return nil, fmt.Errorf("failed to delete published version: %w", err)
	}

	// Promote changed to published
	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, changed.ID, model.StatusPublished, "")
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

	// If trashing a published widget that has a changed copy, also trash the changed copy
	groupID := widget.GroupID
	if groupID == "" {
		groupID = widget.ID
	}

	if widget.Status == model.StatusPublished {
		changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
		if err != nil {
			return nil, err
		}
		if changed != nil {
			// Delete the changed copy when trashing published
			if err := s.WidgetRepo.DeleteByGroupAndStatus(ctx, groupID, model.StatusChanged); err != nil {
				return nil, fmt.Errorf("failed to delete changed copy: %w", err)
			}
		}
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
