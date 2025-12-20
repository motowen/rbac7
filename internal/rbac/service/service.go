package service

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"

	"go.mongodb.org/mongo-driver/mongo"
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
	AssignSystemUserRole(ctx context.Context, callerID string, req model.SystemUserRole) error
	DeleteSystemUserRole(ctx context.Context, callerID, namespace, userID string) error
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

	// 2. Check permissions: Caller must be a moderator (Global, no namespace needed)
	isModerator, err := s.Repo.HasSystemRole(ctx, callerID, "", model.RoleSystemModerator)
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

func (s *Service) AssignSystemUserRole(ctx context.Context, callerID string, req model.SystemUserRole) error {
	if err := s.validateCallerAndNamespace(callerID, req.Namespace); err != nil {
		return err
	}
	if req.UserID == "" {
		return ErrBadRequest
	}
	if req.Role == model.RoleSystemOwner {
		return ErrForbidden
	}
	if req.Role != "admin" && req.Role != "viewer" && req.Role != "editor" && req.Role != "moderator" {
		return ErrBadRequest
	}

	canAssign, err := s.Repo.HasAnySystemRole(ctx, callerID, req.Namespace, []string{model.RoleSystemOwner, model.RoleSystemAdmin})
	if err != nil {
		return err
	}
	if !canAssign {
		return ErrForbidden
	}

	currentOwner, err := s.Repo.GetSystemOwner(ctx, req.Namespace)
	if err != nil {
		return err
	}
	if currentOwner != nil && currentOwner.UserID == req.UserID {
		count, err := s.Repo.CountSystemOwners(ctx, req.Namespace)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrForbidden
		}
	}

	role := &model.UserRole{
		UserID:    req.UserID,
		Role:      req.Role,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserType:  req.UserType,
	}
	if role.UserType == "" {
		role.UserType = model.UserTypeMember
	}
	return s.Repo.UpsertUserRole(ctx, role)
}

func (s *Service) DeleteSystemUserRole(ctx context.Context, callerID, namespace, userID string) error {
	if err := s.validateCallerAndNamespace(callerID, namespace); err != nil {
		return err
	}
	if userID == "" {
		return ErrBadRequest
	}

	canDelete, err := s.Repo.HasAnySystemRole(ctx, callerID, namespace, []string{model.RoleSystemOwner, model.RoleSystemAdmin})
	if err != nil {
		return err
	}
	if !canDelete {
		return ErrForbidden
	}

	currentOwner, err := s.Repo.GetSystemOwner(ctx, namespace)
	if err != nil {
		return err
	}
	if currentOwner != nil && currentOwner.UserID == userID {
		count, err := s.Repo.CountSystemOwners(ctx, namespace)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrForbidden
		}
	}

	err = s.Repo.DeleteUserRole(ctx, namespace, userID, model.ScopeSystem)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}
	return nil
}

func (s *Service) validateRequest(callerID string, req model.SystemOwnerUpsertRequest) error {
	if err := s.validateCallerAndNamespace(callerID, req.Namespace); err != nil {
		return err
	}
	if req.UserID == "" {
		return ErrBadRequest
	}
	return nil
}

func (s *Service) validateCallerAndNamespace(callerID, namespace string) error {
	if callerID == "" {
		return ErrUnauthorized
	}
	if namespace == "" {
		return ErrInvalidNamespace
	}
	return nil
}
