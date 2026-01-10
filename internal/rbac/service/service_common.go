package service

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/policy"
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
	AssignSystemOwner(ctx context.Context, callerID string, req model.AssignSystemOwnerReq) error
	TransferSystemOwner(ctx context.Context, callerID string, req model.TransferSystemOwnerReq) error
	AssignSystemUserRole(ctx context.Context, callerID string, req model.AssignSystemUserRoleReq) error
	AssignSystemUserRoles(ctx context.Context, callerID string, req model.AssignSystemUserRolesReq) (*model.BatchUpsertResult, error) // Batch
	DeleteSystemUserRole(ctx context.Context, callerID string, req model.DeleteSystemUserRoleReq) error
	GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error)
	GetUserRoles(ctx context.Context, callerID string, req model.GetUserRolesReq) ([]*model.UserRole, error)
	AssignResourceOwner(ctx context.Context, callerID string, req model.AssignResourceOwnerReq) error
	TransferResourceOwner(ctx context.Context, callerID string, req model.TransferResourceOwnerReq) error
	AssignResourceUserRole(ctx context.Context, callerID string, req model.AssignResourceUserRoleReq) error
	AssignResourceUserRoles(ctx context.Context, callerID string, req model.AssignResourceUserRolesReq) (*model.BatchUpsertResult, error) // Batch
	DeleteResourceUserRole(ctx context.Context, callerID string, req model.DeleteResourceUserRoleReq) error
	CheckPermission(ctx context.Context, callerID string, req model.CheckPermissionReq) (bool, error)
	// Library Widget
	AssignLibraryWidgetViewers(ctx context.Context, callerID string, req model.AssignLibraryWidgetViewersReq) (*model.BatchUpsertResult, error)
	DeleteLibraryWidgetViewer(ctx context.Context, callerID string, req model.DeleteLibraryWidgetViewerReq) error
}

type Service struct {
	Repo   repository.RBACRepository
	Policy *policy.Engine
}

func NewService(repo repository.RBACRepository) *Service {
	policyEngine, err := policy.NewEngine()
	if err != nil {
		// Policy engine is essential, panic if it fails to load
		panic("failed to initialize policy engine: " + err.Error())
	}
	return &Service{Repo: repo, Policy: policyEngine}
}

func (s *Service) GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error) {
	// Get All My Roles first
	filter := model.UserRoleFilter{UserID: callerID}
	if req.Scope != "" {
		filter.Scope = req.Scope
	}
	if req.ResourceType != "" {
		filter.ResourceType = req.ResourceType
	}

	roles, err := s.Repo.FindUserRoles(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Permission Check using PolicyEngine (auto-infers entity from scope)
	if !s.Policy.CheckSelfRolesPermission(roles, req.Scope, req.ResourceType) {
		return nil, ErrForbidden
	}

	return roles, nil
}

func (s *Service) GetUserRoles(ctx context.Context, callerID string, req model.GetUserRolesReq) ([]*model.UserRole, error) {
	// Permission Check using PolicyEngine (auto-infers entity from scope)
	canList, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:         callerID,
		Operation:        "get_members",
		Scope:            req.Scope,
		Namespace:        req.Namespace,
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
	})
	if err != nil {
		return nil, err
	}
	if !canList {
		return nil, ErrForbidden
	}

	filter := model.UserRoleFilter{
		UserID:       req.UserID,
		Namespace:    req.Namespace,
		Role:         req.Role,
		Scope:        req.Scope,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
	}

	return s.Repo.FindUserRoles(ctx, filter)
}

func (s *Service) CheckPermission(ctx context.Context, callerID string, req model.CheckPermissionReq) (bool, error) {
	if req.Scope == model.ScopeSystem {
		// Use internal method to check the actual permission requested
		return s.checkSystemPermissionInternal(ctx, callerID, req.Namespace, req.Permission)
	} else if req.Scope == model.ScopeResource {
		// Use PolicyEngine's CheckResourceAccess for dashboard_widget inheritance logic
		return s.Policy.CheckResourceAccess(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, req.Permission, req.ParentResourceID)
	}

	return false, ErrBadRequest
}

// checkSystemPermissionInternal checks system permission using PolicyEngine's internal methods
func (s *Service) checkSystemPermissionInternal(ctx context.Context, callerID, namespace, permission string) (bool, error) {
	// Get roles that have this permission (from PolicyEngine's role mappings)
	requiredRoles := s.Policy.GetRolesWithPermission(permission, true)
	if len(requiredRoles) == 0 {
		return false, nil
	}
	return s.Repo.HasAnySystemRole(ctx, callerID, namespace, requiredRoles)
}
