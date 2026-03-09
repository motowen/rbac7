package service

import (
	"context"
	"errors"
	"rbac7/internal/rbac/identity"
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
	AssignSystemUserRoles(ctx context.Context, callerID string, req model.AssignSystemUserRolesReq) (*model.BatchUpsertResult, error)
	DeleteSystemUserRole(ctx context.Context, callerID string, req model.DeleteSystemUserRoleReq) error
	GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error)
	GetUserRoles(ctx context.Context, callerID string, req model.GetUserRolesReq) ([]*model.UserRole, error)
	AssignResourceOwner(ctx context.Context, callerID string, req model.AssignResourceOwnerReq) error
	TransferResourceOwner(ctx context.Context, callerID string, req model.TransferResourceOwnerReq) error
	AssignResourceUserRole(ctx context.Context, callerID string, req model.AssignResourceUserRoleReq) error
	AssignResourceUserRoles(ctx context.Context, callerID string, req model.AssignResourceUserRolesReq) (*model.BatchUpsertResult, error)
	DeleteResourceUserRole(ctx context.Context, callerID string, req model.DeleteResourceUserRoleReq) error
	CheckPermission(ctx context.Context, callerID string, req model.CheckPermissionReq) (bool, error)
	BatchCheckPermission(ctx context.Context, callerID string, req model.BatchCheckPermissionReq) (map[string]bool, error)
	SoftDeleteResource(ctx context.Context, callerID string, req *model.SoftDeleteResourceReq) error
	GetDashboardResource(ctx context.Context, callerID string, req model.GetDashboardResourceReq) (*model.GetDashboardResourceResp, error)
	GetUserRoleHistory(ctx context.Context, callerID string, req model.GetUserRoleHistoryReq) (*model.GetUserRoleHistoryResp, error)
}

type Service struct {
	Repo        repository.RBACRepository
	HistoryRepo repository.HistoryRepository
	OrgUserRepo repository.OrgUserRepository
	Policy      *policy.Engine
}

func NewService(repo repository.RBACRepository, historyRepo repository.HistoryRepository) *Service {
	policyEngine, err := policy.NewEngine()
	if err != nil {
		panic("failed to initialize policy engine: " + err.Error())
	}
	return &Service{Repo: repo, HistoryRepo: historyRepo, Policy: policyEngine}
}

func NewServiceWithOrg(repo repository.RBACRepository, historyRepo repository.HistoryRepository, orgUserRepo repository.OrgUserRepository) *Service {
	svc := NewService(repo, historyRepo)
	svc.OrgUserRepo = orgUserRepo
	return svc
}

func (s *Service) callerContext(ctx context.Context, callerID string) (identity.CallerContext, error) {
	if caller, ok := identity.CallerFromContext(ctx); ok {
		if caller.UserID == "" {
			return identity.CallerContext{}, ErrUnauthorized
		}
		return caller, nil
	}

	if callerID == "" {
		return identity.CallerContext{}, ErrUnauthorized
	}

	return identity.CallerContext{UserID: callerID}, nil
}

func (s *Service) GetUserRolesMe(ctx context.Context, callerID string, req model.GetUserRolesMeReq) ([]*model.UserRole, error) {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return nil, err
	}

	filter := model.UserRoleFilter{UserID: caller.UserID}
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

	if !s.Policy.CheckSelfRolesPermission(roles, req.Scope, req.ResourceType) {
		return nil, ErrForbidden
	}

	return roles, nil
}

func (s *Service) GetUserRoles(ctx context.Context, callerID string, req model.GetUserRolesReq) ([]*model.UserRole, error) {
	if _, err := s.callerContext(ctx, callerID); err != nil {
		return nil, err
	}

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
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return false, err
	}

	var memberAllowed bool

	if req.Scope == model.ScopeSystem {
		memberAllowed, err = s.checkSystemPermissionInternal(ctx, caller.UserID, req.Namespace, req.Permission)
	} else if req.Scope == model.ScopeResource {
		memberAllowed, err = s.Policy.CheckResourceAccess(ctx, s.Repo, caller.UserID, req.ResourceID, req.ResourceType, req.Permission, req.ParentResourceID)
	} else {
		return false, ErrBadRequest
	}

	if err != nil {
		return false, err
	}
	if memberAllowed {
		return true, nil
	}

	orgAllowed, err := s.checkOrgPermission(ctx, caller.UserID, req.Scope, req.Namespace, req.ResourceID, req.ResourceType, req.Permission)
	if err != nil {
		return false, err
	}
	return orgAllowed, nil
}

func (s *Service) BatchCheckPermission(ctx context.Context, callerID string, req model.BatchCheckPermissionReq) (map[string]bool, error) {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return nil, err
	}

	results := make(map[string]bool, len(req.ResourceIDs))

	for _, resourceID := range req.ResourceIDs {
		allowed, err := s.Policy.CheckResourceAccess(ctx, s.Repo, caller.UserID, resourceID, req.ResourceType, req.Permission, "")
		if err != nil {
			return nil, err
		}

		if !allowed {
			orgAllowed, err := s.checkOrgPermission(ctx, caller.UserID, model.ScopeResource, "", resourceID, req.ResourceType, req.Permission)
			if err != nil {
				return nil, err
			}
			allowed = orgAllowed
		}

		results[resourceID] = allowed
	}

	return results, nil
}

func (s *Service) checkOrgPermission(ctx context.Context, callerID, scope, namespace, resourceID, resourceType, permission string) (bool, error) {
	if s.OrgUserRepo == nil {
		return false, nil
	}

	orgUser, err := s.OrgUserRepo.GetOrgUser(ctx, callerID)
	if err != nil {
		return false, err
	}
	if orgUser == nil {
		return false, nil
	}

	orgIDs := orgUser.OrgIDs()
	if len(orgIDs) == 0 {
		return false, nil
	}

	orgRoles, err := s.Repo.FindUserRolesByUserIDs(ctx, orgIDs, model.UserTypeOrg, scope, namespace, resourceID, resourceType)
	if err != nil {
		return false, err
	}
	if len(orgRoles) == 0 {
		return false, nil
	}

	maxRole := s.Policy.GetMaxRole(orgRoles)
	if maxRole == "" {
		return false, nil
	}

	isSystem := scope == model.ScopeSystem
	return s.Policy.RoleHasPermission(maxRole, permission, isSystem), nil
}

func (s *Service) checkSystemPermissionInternal(ctx context.Context, callerID, namespace, permission string) (bool, error) {
	requiredRoles := s.Policy.GetRolesWithPermission(permission, true)
	if len(requiredRoles) == 0 {
		return false, nil
	}
	return s.Repo.HasAnySystemRole(ctx, callerID, namespace, requiredRoles)
}

func (s *Service) GetUserRoleHistory(ctx context.Context, callerID string, req model.GetUserRoleHistoryReq) (*model.GetUserRoleHistoryResp, error) {
	if _, err := s.callerContext(ctx, callerID); err != nil {
		return nil, err
	}

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
