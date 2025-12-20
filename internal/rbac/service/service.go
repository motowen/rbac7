package service

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
)

var (
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrConflict         = errors.New("conflict: system owner already exists")
	ErrInvalidNamespace = errors.New("invalid namespace")
	ErrBadRequest       = errors.New("bad request")
)

type RBACService interface {
	AssignSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error
	TransferSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error
}

type Service struct {
	Repo repository.RBACRepository
}

func NewService(repo repository.RBACRepository) *Service {
	return &Service{Repo: repo}
}

func (s *Service) AssignSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error {
	// 0. Validate Caller & Input
	if err := s.validateRequest(callerID, req); err != nil {
		return err
	}

	// 2. Check permissions: Caller must be a moderator
	isModerator, err := s.Repo.HasSystemRole(ctx, callerID, model.RoleSystemModerator)
	if err != nil {
		return err
	}
	if !isModerator {
		return ErrForbidden
	}

	// 3. Create new UserRole
	newRole := &model.UserRole{
		UserID:    req.UserID,
		Role:      model.RoleSystemOwner,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserType:  model.UserTypeMember, // Defaulting to member as per likely requirement
	}

	err = s.Repo.CreateUserRole(ctx, newRole)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return ErrConflict
		}
		return err
	}

	return nil
}

func (s *Service) TransferSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error {
	// 0. Validate Caller & Input
	if err := s.validateRequest(callerID, req); err != nil {
		return err
	}
	// Cannot transfer to self
	if req.UserID == callerID {
		return ErrBadRequest
	}

	// 2. Check permissions: Caller must be OWNER of this namespace
	// Not just any owner, but owner of THIS system
	// GetSystemOwner returns the owner of the namespace.
	// Easier: Check DB via HasSystemRole logic but specifically for this namespace + owner role
	// Actually repo.GetSystemOwner(ctx, req.Namespace) returns the user role.

	currentOwner, err := s.Repo.GetSystemOwner(ctx, req.Namespace)
	if err != nil {
		return err
	}
	if currentOwner == nil {
		return errors.New("system not found or has no owner")
	}

	if currentOwner.UserID != callerID {
		// Caller is not the owner
		return ErrForbidden
	}

	// 3. Perform Transfer (Transaction)
	// New owner is req.UserID
	err = s.Repo.TransferSystemOwner(ctx, req.Namespace, callerID, req.UserID)
	if err != nil {
		// Map errors if needed, or return generic
		return err
	}

	return nil
}

func (s *Service) validateRequest(callerID string, req model.SystemOwnerUpsertRequest) error {
	if callerID == "" {
		return ErrUnauthorized
	}
	if req.Namespace == "" {
		return ErrInvalidNamespace
	}
	if req.UserID == "" {
		return ErrBadRequest
	}
	return nil
}
