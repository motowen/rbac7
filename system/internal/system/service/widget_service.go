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
// 1. check if widget in draft or changed status
// 2. check is locked by other
// 3. save current published to history (with auto version)
// 4. delete published version and promote changed to published
func (s *WidgetService) Publish(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	// Step 1: check status is draft or changed
	if widget.Status != model.StatusDraft && widget.Status != model.StatusChanged {
		return nil, fmt.Errorf("can only publish from draft or changed status (current: %s)", widget.Status)
	}

	groupID := widget.GroupID
	if groupID == "" {
		groupID = widget.ID
	}

	// Step 2: check lock
	if err := s.Entity.EnsureNotLockedByOther(ctx, model.EntityTypeLibraryWidget, widgetID, callerID); err != nil {
		return nil, err
	}

	if widget.Status == model.StatusDraft {
		// Publishing from draft: just change status
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
		return nil, fmt.Errorf("no changed version found to publish")
	}

	if err := model.ValidateStatusTransition(changed.Status, model.StatusPublished); err != nil {
		return nil, err
	}

	// Step 3: save current published version to history
	if err := s.WidgetRepo.SaveToHistory(ctx, groupID, callerID); err != nil {
		return nil, fmt.Errorf("failed to save history: %w", err)
	}

	// Step 4: delete published version and promote changed
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
		return nil, fmt.Errorf("library widget not found")
	}

	if err := model.ValidateStatusTransition(widget.Status, model.StatusTrashed); err != nil {
		return nil, err
	}

	groupID := widget.GroupID
	if groupID == "" {
		groupID = widget.ID
	}

	// If trashing a published widget that has a changed copy, also delete the changed copy
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
// 1. check if widget in trashed status
// 2. check if there's any history record (indicating it was published before)
// 3. determine target status based on history (draft or published)
// 4. restore the trashed widget to appropriate status
func (s *WidgetService) Restore(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
	widget, err := s.WidgetRepo.GetLibraryWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}
	if widget == nil {
		return nil, fmt.Errorf("library widget not found")
	}

	// Step 1: check trashed status
	if widget.Status != model.StatusTrashed {
		return nil, fmt.Errorf("can only restore trashed widget")
	}

	groupID := widget.GroupID
	if groupID == "" {
		groupID = widget.ID
	}

	// Step 2 & 3: check history to determine target status
	latestHistory, err := s.WidgetRepo.GetLatestHistory(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to check history: %w", err)
	}

	var targetStatus string
	if latestHistory != nil {
		// Has history → was published before → restore to published
		targetStatus = model.StatusPublished
	} else {
		// No history → never published → restore to draft
		targetStatus = model.StatusDraft
	}

	// Step 4: restore
	return s.WidgetRepo.UpdateLibraryWidgetStatus(ctx, widgetID, targetStatus, "")
}

// Revert reverts a published widget to a specific history version
// 1. check if widget in published status
// 2. find history record by version
// 3. get latest version number for next version
// 4. create new history record (saving current published)
// 5. update current widget with the reverted data
func (s *WidgetService) Revert(ctx context.Context, callerID, widgetID string, version int) (*model.LibraryWidget, error) {
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

	// Step 1: check published status — find the published version
	published, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusPublished)
	if err != nil {
		return nil, err
	}
	if published == nil {
		return nil, fmt.Errorf("can only revert published widget")
	}

	// Step 2: find history record by version
	historyRecord, err := s.WidgetRepo.GetHistoryByVersion(ctx, groupID, version)
	if err != nil {
		return nil, err
	}
	if historyRecord == nil {
		return nil, fmt.Errorf("history version %d not found", version)
	}

	// Step 3 & 4: save current published to history (auto-determines next version)
	if err := s.WidgetRepo.SaveToHistory(ctx, groupID, callerID); err != nil {
		return nil, fmt.Errorf("failed to save current version to history: %w", err)
	}

	// Step 5: update current published widget with reverted data
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
// 1. check is locked by me (not locked by other)
// 2. check if changed version exists
// 3. delete changed version
// 4. return published version
func (s *WidgetService) Discard(ctx context.Context, callerID, widgetID string) (*model.LibraryWidget, error) {
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

	// Step 1: check lock
	if err := s.Entity.EnsureNotLockedByOther(ctx, model.EntityTypeLibraryWidget, widgetID, callerID); err != nil {
		return nil, err
	}

	// Step 2: find changed version
	changed, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusChanged)
	if err != nil {
		return nil, err
	}
	if changed == nil {
		return nil, fmt.Errorf("no changed version to discard")
	}

	// Step 3: delete changed version
	if err := s.WidgetRepo.DeleteByGroupAndStatus(ctx, groupID, model.StatusChanged); err != nil {
		return nil, fmt.Errorf("failed to delete changed version: %w", err)
	}

	// Step 4: return published version
	published, err := s.WidgetRepo.GetByGroupAndStatus(ctx, groupID, model.StatusPublished)
	if err != nil {
		return nil, err
	}
	if published == nil {
		return nil, fmt.Errorf("published version not found")
	}

	return published, nil
}
