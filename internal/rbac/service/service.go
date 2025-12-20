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
}

type Service struct {
	Repo repository.RBACRepository
}

func NewService(repo repository.RBACRepository) *Service {
	return &Service{Repo: repo}
}

func (s *Service) AssignSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error {
	// 0. Validate Caller
	if callerID == "" {
		return ErrUnauthorized
	}

	// 1. Validate Input
	if req.Namespace == "" {
		return ErrInvalidNamespace
	}
	if req.UserID == "" {
		return ErrBadRequest
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
