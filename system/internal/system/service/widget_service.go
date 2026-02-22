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

// resolveGroupID returns the effective group ID for a widget
func resolveGroupID(widget *model.LibraryWidget) string {
	if widget.GroupID != "" {
		return widget.GroupID
	}
	return widget.ID
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
		return nil, ErrWidgetNotFound
	}

	groupID := resolveGroupID(widget)

	switch widget.Status {
	case model.StatusDraft:
		if err := s.Entity.EnsureEditable(ctx, model.EntityTypeLibraryWidget, widgetID, callerID, widget.Status); err != nil {
			return nil, err
		}
		return s.WidgetRepo.UpdateLibraryWidget(ctx, widgetID, update)

	case model.StatusPublished:
		changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
		if err != nil {
			return nil, err
		}
		if changed != nil {
			if err := s.Entity.EnsureEditable(ctx, model.EntityTypeLibraryWidget, widgetID, callerID, model.StatusChanged); err != nil {
				return nil, err
			}
			return s.WidgetRepo.UpdateLibraryWidget(ctx, changed.ID, update)
		}
		changed, err = s.WidgetRepo.CopyToChanged(ctx, groupID)
		if err != nil {
			return nil, fmt.Errorf("failed to create changed copy: %w", err)
		}
		result, err := s.WidgetRepo.UpdateLibraryWidget(ctx, changed.ID, update)
		if err != nil {
			return nil, fmt.Errorf("failed to update changed copy: %w", err)
		}
		return result, nil

	case model.StatusChanged:
		if err := s.Entity.EnsureEditable(ctx, model.EntityTypeLibraryWidget, widgetID, callerID, widget.Status); err != nil {
			return nil, err
		}
		return s.WidgetRepo.UpdateLibraryWidget(ctx, widgetID, update)

	default:
		return nil, fmt.Errorf("%w: cannot update in %s status", ErrInvalidWidgetStatus, widget.Status)
	}
}

// Publish transitions library widget from draft/changed → published
func (s *WidgetService) Publish(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, ErrWidgetNotFound
	}

	if widget.Status != model.StatusDraft && widget.Status != model.StatusChanged {
		return nil, fmt.Errorf("%w: can only publish from draft or changed (current: %s)", ErrInvalidWidgetStatus, widget.Status)
	}

	groupID := resolveGroupID(widget)

	if err := s.Entity.EnsureNotLockedByOther(ctx, model.EntityTypeLibraryWidget, widgetID, callerID); err != nil {
		return nil, err
	}

	if widget.Status == model.StatusDraft {
		if err := model.ValidateStatusTransition(widget.Status, model.StatusPublished); err != nil {
			return nil, err
		}
		return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, model.StatusPublished, "")
	}

	// Publishing from changed
	changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
	if err != nil {
		return nil, err
	}
	if widget.Status == model.StatusChanged {
		changed = widget
	}
	if changed == nil {
		return nil, ErrNoChangedVersion
	}

	if err := model.ValidateStatusTransition(changed.Status, model.StatusPublished); err != nil {
		return nil, err
	}

	if err := s.WidgetRepo.SaveToHistory(ctx, groupID, callerID); err != nil {
		return nil, fmt.Errorf("failed to save history: %w", err)
	}

	if err := s.WidgetRepo.DeleteByGroupAndStatus(ctx, groupID, model.StatusPublished); err != nil {
		return nil, fmt.Errorf("failed to delete published version: %w", err)
	}

	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, changed.ID, model.StatusPublished, "")
}

// Trash transitions library widget to trashed (soft delete)
func (s *WidgetService) Trash(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, ErrWidgetNotFound
	}

	if err := model.ValidateStatusTransition(widget.Status, model.StatusTrashed); err != nil {
		return nil, err
	}

	groupID := resolveGroupID(widget)

	if widget.Status == model.StatusPublished {
		changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
		if err != nil {
			return nil, err
		}
		if changed != nil {
			if err := s.WidgetRepo.DeleteByGroupAndStatus(ctx, groupID, model.StatusChanged); err != nil {
				return nil, fmt.Errorf("failed to delete changed copy: %w", err)
			}
		}
	}

	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, model.StatusTrashed, widget.Status)
}

// Restore transitions library widget from trashed → appropriate status
func (s *WidgetService) Restore(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, ErrWidgetNotFound
	}

	if widget.Status != model.StatusTrashed {
		return nil, fmt.Errorf("%w: can only restore trashed widget (current: %s)", ErrInvalidWidgetStatus, widget.Status)
	}

	groupID := resolveGroupID(widget)

	latestHistory, err := s.WidgetRepo.GetLatestHistory(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to check history: %w", err)
	}

	var targetStatus string
	if latestHistory != nil {
		targetStatus = model.StatusPublished
	} else {
		targetStatus = model.StatusDraft
	}

	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, targetStatus, "")
}

// Revert reverts a published widget to a specific history version
func (s *WidgetService) Revert(ctx context.Context, callerID, widgetID string, version int) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, ErrWidgetNotFound
	}

	groupID := resolveGroupID(widget)

	published, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusPublished)
	if err != nil {
		return nil, err
	}
	if published == nil {
		return nil, fmt.Errorf("%w: can only revert published widget", ErrInvalidWidgetStatus)
	}

	historyRecord, err := s.WidgetRepo.GetHistoryByVersion(ctx, groupID, version)
	if err != nil {
		return nil, err
	}
	if historyRecord == nil {
		return nil, fmt.Errorf("%w: version %d", ErrHistoryVersionNotFound, version)
	}

	if err := s.WidgetRepo.SaveToHistory(ctx, groupID, callerID); err != nil {
		return nil, fmt.Errorf("failed to save current version to history: %w", err)
	}

	snapshot := historyRecord.Snapshot.Widget
	revertUpdate := &repository.LibraryWidgetUpdate{
		Name:         &snapshot.Name,
		Version:      &snapshot.Version,
		Type:         &snapshot.Type,
		TypeVersion:  &snapshot.TypeVersion,
		Schema:       snapshot.Schema,
		Datasource:   snapshot.Datasource,
		ThumbnailURL: &snapshot.ThumbnailURL,
		DisplayMode:  &snapshot.DisplayMode,
		Tags:         snapshot.Tags,
		UserConfig:   snapshot.UserConfig,
	}

	return s.WidgetRepo.UpdateLibraryWidget(ctx, published.ID, revertUpdate)
}

// Discard discards the changed version and keeps the published version
func (s *WidgetService) Discard(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, ErrWidgetNotFound
	}

	groupID := resolveGroupID(widget)

	if err := s.Entity.EnsureNotLockedByOther(ctx, model.EntityTypeLibraryWidget, widgetID, callerID); err != nil {
		return nil, err
	}

	changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
	if err != nil {
		return nil, err
	}
	if changed == nil {
		return nil, ErrNoChangedVersion
	}

	if err := s.WidgetRepo.DeleteByGroupAndStatus(ctx, groupID, model.StatusChanged); err != nil {
		return nil, fmt.Errorf("failed to delete changed version: %w", err)
	}

	published, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusPublished)
	if err != nil {
		return nil, err
	}
	if published == nil {
		return nil, ErrNoPublishedVersion
	}

	return published, nil
}
