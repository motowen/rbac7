package service

import (
	"context"
	"fmt"
	"time"

	"system/internal/system/model"
	"system/internal/system/repository"
)

// EntityService provides shared lock and status validation logic
type EntityService struct {
	LockRepo repository.LockRepository
}

// NewEntityService creates a new EntityService
func NewEntityService(lockRepo repository.LockRepository) *EntityService {
	return &EntityService{LockRepo: lockRepo}
}

// EnsureNotLockedByOther checks that the entity is not locked by another user.
// Returns nil if not locked or locked by the same user.
func (s *EntityService) EnsureNotLockedByOther(ctx context.Context, entityType, entityID, callerID string) error {
	locked, err := s.LockRepo.IsLockedByOther(ctx, entityType, entityID, callerID)
	if err != nil {
		return err
	}
	if locked {
		return repository.ErrLocked
	}
	return nil
}

// EnsureEditable checks that the entity status allows editing (draft/changed) and not locked by another user.
func (s *EntityService) EnsureEditable(ctx context.Context, entityType, entityID, callerID, status string) error {
	if err := s.EnsureNotLockedByOther(ctx, entityType, entityID, callerID); err != nil {
		return err
	}
	if !model.IsEditable(status) {
		return fmt.Errorf("entity is not in an editable status (current: %s)", status)
	}
	return nil
}

// Lock acquires a lock on the entity
func (s *EntityService) Lock(ctx context.Context, entityType, entityID, callerID string) (*model.EntityLock, error) {
	return s.LockRepo.Lock(ctx, entityType, entityID, callerID, 5*time.Minute)
}

// Unlock releases a lock on the entity
func (s *EntityService) Unlock(ctx context.Context, entityType, entityID, callerID string) error {
	return s.LockRepo.Unlock(ctx, entityType, entityID, callerID)
}

// GetLock returns the current lock info for an entity, or nil if not locked
func (s *EntityService) GetLock(ctx context.Context, entityType, entityID string) (*model.EntityLock, error) {
	return s.LockRepo.GetLock(ctx, entityType, entityID)
}
