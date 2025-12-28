package service

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
	"strings"
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
	DeleteSystemUserRole(ctx context.Context, callerID string, req model.DeleteSystemUserRoleReq) error
	GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error)
	GetUserRoles(ctx context.Context, callerID string, filter model.UserRoleFilter) ([]*model.UserRole, error)
	AssignResourceOwner(ctx context.Context, callerID string, req model.ResourceOwnerUpsertRequest) error
	TransferResourceOwner(ctx context.Context, callerID string, req model.ResourceOwnerUpsertRequest) error
	AssignResourceUserRole(ctx context.Context, callerID string, req model.ResourceUserRole) error
	DeleteResourceUserRole(ctx context.Context, callerID string, req model.DeleteResourceUserRoleReq) error
	CheckPermission(ctx context.Context, callerID string, req model.CheckPermissionRequest) (bool, error)
}

type Service struct {
	Repo repository.RBACRepository
}

func NewService(repo repository.RBACRepository) *Service {
	return &Service{Repo: repo}
}

func (s *Service) GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error) {
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	resourceType := strings.ToLower(strings.TrimSpace(req.ResourceType))

	// Get All My Roles first
	filter := model.UserRoleFilter{UserID: callerID}
	if scope != "" {
		filter.Scope = scope
	}
	if resourceType != "" {
		filter.ResourceType = resourceType
	}

	roles, err := s.Repo.FindUserRoles(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Permission Check
	if scope == model.ScopeSystem {
		// Requirement: "GetUserRolesMe要檢查有沒有platform.system.read的權限"
		if !CheckRolesHavePermission(roles, PermPlatformSystemRead) {
			return nil, ErrForbidden
		}
	} else if scope == model.ScopeResource {
		// For resource scope, check resource read permission
		// Given strict RBAC, let's use the one matching resourceType.
		perm := "resource." + resourceType + ".read"
		// If resourceType is present:
		if resourceType != "" {
			if !CheckRolesHavePermission(roles, perm) {
				return nil, ErrForbidden
			}
		} else {
			// If resourceType not provided (e.g. get all my resources), strict check might fail.
			// But sticking to test requirement "missing resource_type -> 400" in Handler, so resourceType will be present.
			// Just in case:
			if !CheckRolesHavePermission(roles, PermResourceDashboardRead) { // Fallback or Fail?
				// If we have mixed resources, we need mixed check.
				// But let's assume resourceType is mandatory for 'resource' scope for now.
				return nil, ErrForbidden
			}
		}
	}

	return roles, nil
}

func (s *Service) GetUserRoles(ctx context.Context, callerID string, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	filter.Namespace = strings.ToUpper(strings.TrimSpace(filter.Namespace))
	filter.Role = strings.ToLower(strings.TrimSpace(filter.Role))
	filter.Scope = strings.ToLower(strings.TrimSpace(filter.Scope))
	filter.UserID = strings.TrimSpace(filter.UserID)

	// Permission Check for List
	if filter.Scope == model.ScopeSystem {
		// Permission: platform.system.get_member
		// Note: User user request 1186: GetUserRoles -> get_meber (get_member)

		canList, err := CheckSystemPermission(ctx, s.Repo, callerID, filter.Namespace, PermPlatformSystemGetMember)
		if err != nil {
			return nil, err
		}
		if !canList {
			return nil, ErrForbidden
		}
	} else if filter.Scope == model.ScopeResource {
		// Permission: resource.{type}.get_member
		if filter.ResourceID == "" || filter.ResourceType == "" {
			return nil, ErrBadRequest // Handler should catch this, but safeguard
		}
		perm := "resource." + filter.ResourceType + ".get_member"
		canList, err := CheckResourcePermission(ctx, s.Repo, callerID, filter.ResourceID, filter.ResourceType, perm)
		if err != nil {
			return nil, err
		}
		if !canList {
			return nil, ErrForbidden
		}
	}

	return s.Repo.FindUserRoles(ctx, filter)
}

func (s *Service) CheckPermission(ctx context.Context, callerID string, req model.CheckPermissionRequest) (bool, error) {
	req.Permission = strings.TrimSpace(req.Permission)
	req.Scope = strings.ToLower(strings.TrimSpace(req.Scope))

	if req.Permission == "" || req.Scope == "" {
		return false, ErrBadRequest
	}

	if req.Scope == model.ScopeSystem {
		req.Namespace = strings.ToUpper(strings.TrimSpace(req.Namespace))
		return CheckSystemPermission(ctx, s.Repo, callerID, req.Namespace, req.Permission)
	} else if req.Scope == model.ScopeResource {
		req.ResourceID = strings.TrimSpace(req.ResourceID)
		req.ResourceType = strings.ToLower(strings.TrimSpace(req.ResourceType))

		if req.ResourceID == "" || req.ResourceType == "" {
			return false, ErrBadRequest
		}
		return CheckResourcePermission(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, req.Permission)
	}

	return false, ErrBadRequest
}
