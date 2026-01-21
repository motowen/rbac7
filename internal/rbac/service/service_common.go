package service

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"
	"time"
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
	// Resource Management
	SoftDeleteResource(ctx context.Context, callerID string, req *model.SoftDeleteResourceReq) error
	GetDashboardResource(ctx context.Context, callerID string, req model.GetDashboardResourceReq) (*model.GetDashboardResourceResp, error)
	// History
	GetUserRoleHistory(ctx context.Context, callerID string, req model.GetUserRoleHistoryReq) (*model.GetUserRoleHistoryResp, error)
}

type Service struct {
	Repo        repository.RBACRepository
	HistoryRepo repository.HistoryRepository
	Policy      *policy.Engine
}

func NewService(repo repository.RBACRepository, historyRepo repository.HistoryRepository) *Service {
	policyEngine, err := policy.NewEngine()
	if err != nil {
		// Policy engine is essential, panic if it fails to load
		panic("failed to initialize policy engine: " + err.Error())
	}
	return &Service{Repo: repo, HistoryRepo: historyRepo, Policy: policyEngine}
}

func (s *Service) GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error) {
	// Permission check handled by RBAC middleware for self_roles check_scope

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

	// Self-roles permission check: verify caller has read permission
	if !s.Policy.CheckSelfRolesPermission(roles, req.Scope, req.ResourceType) {
		return nil, ErrForbidden
	}

	return roles, nil
}

func (s *Service) GetUserRoles(ctx context.Context, callerID string, req model.GetUserRolesReq) ([]*model.UserRole, error) {
	// Permission check handled by RBAC middleware

	filter := model.UserRoleFilter{
		UserID:           req.UserID,
		Namespace:        req.Namespace,
		Role:             req.Role,
		Scope:            req.Scope,
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
	}

	return s.Repo.FindUserRoles(ctx, filter)
}

func (s *Service) CheckPermission(ctx context.Context, callerID string, req model.CheckPermissionReq) (bool, error) {
	if req.Scope == model.ScopeSystem {
		return s.checkSystemPermissionInternal(ctx, callerID, req.Namespace, req.Permission)
	} else if req.Scope == model.ScopeResource {
		return s.Policy.CheckResourceAccess(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, req.Permission, req.ParentResourceID)
	}

	return false, ErrBadRequest
}

// checkSystemPermissionInternal checks system permission using PolicyEngine's internal methods
func (s *Service) checkSystemPermissionInternal(ctx context.Context, callerID, namespace, permission string) (bool, error) {
	requiredRoles := s.Policy.GetRolesWithPermission(permission, true)
	if len(requiredRoles) == 0 {
		return false, nil
	}
	return s.Repo.HasAnySystemRole(ctx, callerID, namespace, requiredRoles)
}

// GetUserRoleHistory retrieves user role history with pagination
func (s *Service) GetUserRoleHistory(ctx context.Context, callerID string, req model.GetUserRoleHistoryReq) (*model.GetUserRoleHistoryResp, error) {
	// Permission check handled by RBAC middleware

	data, total, err := s.HistoryRepo.FindHistory(ctx, req)
	if err != nil {
		return nil, err
	}

	return &model.GetUserRoleHistoryResp{
		Data:       data,
		Page:       req.Page,
		Size:       req.Size,
		TotalCount: total,
	}, nil
}

// recordHistory is a helper to record history asynchronously (fire-and-forget)
func (s *Service) recordHistory(history *model.UserRoleHistory) {
	if s.HistoryRepo == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.HistoryRepo.CreateHistory(ctx, history)
	}()
}
