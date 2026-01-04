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
	DeleteSystemUserRole(ctx context.Context, callerID string, req model.DeleteSystemUserRoleReq) error
	GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error)
	GetUserRoles(ctx context.Context, callerID string, req model.GetUserRolesReq) ([]*model.UserRole, error)
	AssignResourceOwner(ctx context.Context, callerID string, req model.AssignResourceOwnerReq) error
	TransferResourceOwner(ctx context.Context, callerID string, req model.TransferResourceOwnerReq) error
	AssignResourceUserRole(ctx context.Context, callerID string, req model.AssignResourceUserRoleReq) error
	DeleteResourceUserRole(ctx context.Context, callerID string, req model.DeleteResourceUserRoleReq) error
	CheckPermission(ctx context.Context, callerID string, req model.CheckPermissionReq) (bool, error)
}

type Service struct {
	Repo         repository.RBACRepository
	PolicyEngine *policy.PolicyEngine
}

func NewService(repo repository.RBACRepository) *Service {
	return &Service{
		Repo:         repo,
		PolicyEngine: policy.NewPolicyEngine(),
	}
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

	// Permission Check
	// Permission Check via Policy
	ctxPol := map[string]interface{}{
		"scope":         req.Scope,
		"resource_type": req.ResourceType,
	}

	// Default resource type for resource scope if missing?
	// The original logic had a fallback check for `PermResourceDashboardRead` if resourceType was empty.
	// We can handle this by ensuring `req.ResourceType` corresponds to what we want to interpolate,
	// or by handling the error/defaulting in code.
	// If req.ResourceType is empty, "resource.{resource_type}.read" becomes "resource..read" which is invalid.
	if req.Scope == model.ScopeResource && req.ResourceType == "" {
		// Fallback as per original logic intuition: check for dashboard read? or just fail?
		// Original logic: if resourceType == "", it did a check for PermResourceDashboardRead.
		ctxPol["resource_type"] = "dashboard" // Force default?
	}

	perm, _, err := s.PolicyEngine.GetPermission("get_user_roles_me", ctxPol)
	if err != nil {
		// If no policy found (e.g. unknown scope), maybe return error?
		// But existing logic only checked system/resource.
		// If scope is empty or invalid, handler might have caught it, or we just error out.
		return nil, err
	}

	if !CheckRolesHavePermission(roles, perm) {
		return nil, ErrForbidden
	}

	return roles, nil
}

func (s *Service) GetUserRoles(ctx context.Context, callerID string, req model.GetUserRolesReq) ([]*model.UserRole, error) {
	// Permission Check for List
	// Permission Check via Policy
	ctxPol := map[string]interface{}{
		"scope":         req.Scope,
		"resource_type": req.ResourceType,
	}
	perm, _, err := s.PolicyEngine.GetPermission("get_user_roles", ctxPol)
	if err != nil {
		return nil, err
	}

	if req.Scope == model.ScopeSystem {
		canList, err := CheckSystemPermission(ctx, s.Repo, callerID, req.Namespace, perm)
		if err != nil {
			return nil, err
		}
		if !canList {
			return nil, ErrForbidden
		}
	} else if req.Scope == model.ScopeResource {
		if req.ResourceID == "" || req.ResourceType == "" {
			return nil, ErrBadRequest
		}
		canList, err := CheckResourcePermission(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, perm)
		if err != nil {
			return nil, err
		}
		if !canList {
			return nil, ErrForbidden
		}
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
	// Validation already done in handler/struct validate, but trim is useful helper.
	if req.Permission == "" || req.Scope == "" {
		return false, ErrBadRequest
	}

	if req.Scope == model.ScopeSystem {
		return CheckSystemPermission(ctx, s.Repo, callerID, req.Namespace, req.Permission)
	} else if req.Scope == model.ScopeResource {

		if req.ResourceID == "" || req.ResourceType == "" {
			return false, ErrBadRequest
		}

		// Dashboard Widget Inheritance Logic
		if req.ResourceType == "dashboard_widget" {
			// 1. Check if specific roles exist on this widget (Whitelist)
			count, err := s.Repo.CountResourceRoles(ctx, req.ResourceID, req.ResourceType)
			if err != nil {
				return false, err
			}

			if count > 0 {
				// Whitelist Mode: Strict check on the widget itself.
				return CheckResourcePermission(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, req.Permission)
			}

			// 2. Inheritance Mode: Check Parent Dashboard permissions
			// Only if NO roles are assigned to the widget (Public/Inherited)
			if req.ParentResourceID == "" {
				// If parent ID is missing, we can't check parent.
				// Fail safe: Deny or assume strict check failed (which it did, since count=0 means no roles).
				// However, if count=0, user definitely has NO role on widget.
				// So we MUST return denied if no parent ID.
				return false, ErrBadRequest // Parent ID required for inheritance check
			}

			// Check if user has "resource.dashboard.read" (or similar) on the Parent Dashboard
			// Map widget permission to dashboard permission?
			// Assumption: If I want "read" on widget, I need "read" on dashboard.
			targetPerm := req.Permission
			if targetPerm == model.PermResourceDashboardWidgetRead {
				// Map to Dashboard Read
				targetPerm = model.PermResourceDashboardRead
			}
			// Note: For "ADD" widget, the permission is checked against the DASHBOARD directly in the handler or caller?
			// Actually, "Process Dashboard Widget" usually involves checking "dashboard" permissions.
			// But here we are checking permission ON THE WIDGET resource.
			// If it's a read operation, we check parent.

			return CheckResourcePermission(ctx, s.Repo, callerID, req.ParentResourceID, "dashboard", targetPerm)
		}

		return CheckResourcePermission(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, req.Permission)
	}

	return false, ErrBadRequest
}
