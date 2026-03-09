package service

import (
	"context"
	"errors"
	"log"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"

	"go.mongodb.org/mongo-driver/mongo"
)

func (s *Service) AssignResourceOwner(ctx context.Context, callerID string, req model.AssignResourceOwnerReq) error {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return err
	}

	actorID := caller.UserID
	count, err := s.Repo.CountResourceOwners(ctx, req.ResourceID, req.ResourceType)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrConflict
	}

	newRole := &model.UserRole{
		UserID:       actorID,
		Role:         model.RoleResourceOwner,
		Scope:        model.ScopeResource,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		UserType:     model.UserTypeMember,
		CreatedBy:    actorID,
		UpdatedBy:    actorID,
	}

	err = s.Repo.CreateUserRole(ctx, newRole)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return ErrConflict
		}
		return err
	}

	log.Printf("Audit: Resource Owner Assigned. Caller=%s, Target=%s, Resource=%s:%s", actorID, actorID, req.ResourceType, req.ResourceID)

	s.recordHistory(&model.UserRoleHistory{
		Operation:    "assign_owner",
		CallerID:     actorID,
		Scope:        model.ScopeResource,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		UserID:       actorID,
	})

	return nil
}

func (s *Service) TransferResourceOwner(ctx context.Context, callerID string, req model.TransferResourceOwnerReq) error {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return err
	}

	actorID := caller.UserID
	if req.UserID == actorID {
		return ErrBadRequest
	}

	oldOwnerID := actorID
	err = s.Repo.TransferResourceOwner(ctx, req.ResourceID, req.ResourceType, oldOwnerID, req.UserID, actorID)
	if err != nil {
		return err
	}

	log.Printf("Audit: Resource Owner Transferred. Caller=%s, NewOwner=%s, OldOwner=%s, Resource=%s:%s", actorID, req.UserID, oldOwnerID, req.ResourceType, req.ResourceID)

	s.recordHistory(&model.UserRoleHistory{
		Operation:    "transfer_owner",
		CallerID:     actorID,
		Scope:        model.ScopeResource,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		NewOwnerID:   req.UserID,
	})

	return nil
}

func (s *Service) AssignResourceUserRole(ctx context.Context, callerID string, req model.AssignResourceUserRoleReq) error {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return err
	}

	actorID := caller.UserID
	if req.Role == model.RoleResourceOwner {
		return ErrForbidden
	}
	if req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		return ErrBadRequest
	}

	isOwner, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		return ErrForbidden
	}

	if req.ResourceType == model.ResourceTypeDashboardWidget {
		viewerRoles := s.Policy.GetRolesWithPermission(model.PermResourceDashboardRead, false)
		hasParentAccess, err := s.Repo.HasAnyResourceRole(ctx, req.UserID, req.ParentResourceID, model.ResourceTypeDashboard, viewerRoles)
		if err != nil {
			return err
		}
		if !hasParentAccess {
			return ErrBadRequest
		}
	}

	role := &model.UserRole{
		UserID:           req.UserID,
		Role:             req.Role,
		Scope:            model.ScopeResource,
		Namespace:        "",
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		UserType:         req.UserType,
		CreatedBy:        actorID,
		UpdatedBy:        actorID,
	}
	if role.UserType == "" {
		role.UserType = model.UserTypeMember
	}
	if err := s.Repo.UpsertUserRole(ctx, role); err != nil {
		return err
	}

	log.Printf("Audit: Resource User Role Assigned. Caller=%s, Target=%s, Role=%s, Resource=%s:%s", actorID, req.UserID, req.Role, req.ResourceType, req.ResourceID)

	s.recordHistory(&model.UserRoleHistory{
		Operation:        "assign_user_role",
		CallerID:         actorID,
		Scope:            model.ScopeResource,
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		UserID:           req.UserID,
		UserType:         req.UserType,
		Role:             req.Role,
	})

	return nil
}

func (s *Service) DeleteResourceUserRole(ctx context.Context, callerID string, req model.DeleteResourceUserRoleReq) error {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return err
	}

	actorID := caller.UserID
	if req.UserID == "" || req.ResourceID == "" || req.ResourceType == "" {
		return ErrBadRequest
	}

	isOwner, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		return ErrForbidden
	}

	err = s.Repo.DeleteUserRole(ctx, req.Namespace, req.UserID, model.ScopeResource, req.ResourceID, req.ResourceType, req.ParentResourceID, actorID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	log.Printf("Audit: Resource User Role Deleted. Caller=%s, Target=%s, Resource=%s:%s", actorID, req.UserID, req.ResourceType, req.ResourceID)

	if req.ResourceType == model.ResourceTypeDashboard {
		_ = s.Repo.DeleteUserRolesByParent(ctx, req.UserID, req.ResourceID, model.ResourceTypeDashboardWidget, actorID)
	}

	s.recordHistory(&model.UserRoleHistory{
		Operation:        "delete_user_role",
		CallerID:         actorID,
		Scope:            model.ScopeResource,
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		UserID:           req.UserID,
		UserType:         req.UserType,
		Namespace:        req.Namespace,
	})

	return nil
}

func (s *Service) AssignResourceUserRoles(ctx context.Context, callerID string, req model.AssignResourceUserRolesReq) (*model.BatchUpsertResult, error) {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return nil, err
	}

	actorID := caller.UserID
	validUserIDs := req.UserIDs
	var invalidUsers []model.FailedUserInfo
	if req.ResourceType == model.ResourceTypeDashboardWidget {
		viewerRoles := s.Policy.GetRolesWithPermission(model.PermResourceDashboardRead, false)
		validUserIDs = make([]string, 0, len(req.UserIDs))
		for _, userID := range req.UserIDs {
			hasParentAccess, err := s.Repo.HasAnyResourceRole(ctx, userID, req.ParentResourceID, model.ResourceTypeDashboard, viewerRoles)
			if err != nil {
				return nil, err
			}
			if hasParentAccess {
				validUserIDs = append(validUserIDs, userID)
			} else {
				invalidUsers = append(invalidUsers, model.FailedUserInfo{
					UserID: userID,
					Reason: "user must have parent dashboard read permission",
				})
			}
		}
		if len(validUserIDs) == 0 {
			return &model.BatchUpsertResult{
				SuccessCount: 0,
				FailedCount:  len(invalidUsers),
				FailedUsers:  invalidUsers,
			}, nil
		}
	}

	roles := make([]*model.UserRole, 0, len(validUserIDs))
	userType := req.UserType
	if userType == "" {
		userType = model.UserTypeMember
	}
	for _, userID := range validUserIDs {
		role := &model.UserRole{
			UserID:           userID,
			Role:             req.Role,
			Scope:            model.ScopeResource,
			Namespace:        req.Namespace,
			ResourceID:       req.ResourceID,
			ResourceType:     req.ResourceType,
			ParentResourceID: req.ParentResourceID,
			UserType:         userType,
			CreatedBy:        actorID,
			UpdatedBy:        actorID,
		}
		roles = append(roles, role)
	}

	result, err := s.Repo.BulkUpsertUserRoles(ctx, roles)
	if err != nil {
		return nil, err
	}

	if len(invalidUsers) > 0 {
		result.FailedCount += len(invalidUsers)
		result.FailedUsers = append(result.FailedUsers, invalidUsers...)
	}

	log.Printf("Audit: Resource User Roles Assigned (Batch). Caller=%s, Success=%d, Failed=%d, Role=%s, Resource=%s:%s",
		actorID, result.SuccessCount, result.FailedCount, req.Role, req.ResourceType, req.ResourceID)

	s.recordHistory(&model.UserRoleHistory{
		Operation:        "assign_user_roles_batch",
		CallerID:         actorID,
		Scope:            model.ScopeResource,
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		UserIDs:          req.UserIDs,
		UserType:         req.UserType,
		Role:             req.Role,
		Namespace:        req.Namespace,
	})

	return result, nil
}

func (s *Service) SoftDeleteResource(ctx context.Context, callerID string, req *model.SoftDeleteResourceReq) error {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return err
	}

	actorID := caller.UserID
	if err := s.Repo.SoftDeleteResourceUserRoles(ctx, req, actorID); err != nil {
		return err
	}

	log.Printf("Audit: Resource Soft Deleted. Caller=%s, Resource=%s:%s, ChildResources=%d",
		actorID, req.ResourceType, req.ResourceID, len(req.ChildResourceIDs))

	s.recordHistory(&model.UserRoleHistory{
		Operation:        "delete_resource",
		CallerID:         actorID,
		Scope:            model.ScopeResource,
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		ChildResourceIDs: req.ChildResourceIDs,
	})

	return nil
}

func (s *Service) GetDashboardResource(ctx context.Context, callerID string, req model.GetDashboardResourceReq) (*model.GetDashboardResourceResp, error) {
	caller, err := s.callerContext(ctx, callerID)
	if err != nil {
		return nil, err
	}

	actorID := caller.UserID
	filter := model.UserRoleFilter{
		UserID:       actorID,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		Scope:        model.ScopeResource,
	}
	userRoles, err := s.Repo.FindUserRoles(ctx, filter)
	if err != nil {
		return nil, err
	}

	roleDTOs := make([]*model.UserRoleDTO, 0, len(userRoles))
	for _, role := range userRoles {
		roleDTOs = append(roleDTOs, &model.UserRoleDTO{
			UserID:   role.UserID,
			UserType: role.UserType,
			Role:     role.Role,
		})
	}

	accessibleWidgetIDs := make([]string, 0)
	viewerRoles := s.Policy.GetRolesWithPermission(model.PermResourceDashboardWidgetRead, false)

	for _, widgetID := range req.ChildResourceIDs {
		roleCount, err := s.Repo.CountResourceRoles(ctx, widgetID, "dashboard_widget")
		if err != nil {
			return nil, err
		}

		if roleCount == 0 {
			accessibleWidgetIDs = append(accessibleWidgetIDs, widgetID)
		} else {
			hasRole, err := s.Repo.HasAnyResourceRole(ctx, actorID, widgetID, "dashboard_widget", viewerRoles)
			if err != nil {
				return nil, err
			}
			if hasRole {
				accessibleWidgetIDs = append(accessibleWidgetIDs, widgetID)
			}
		}
	}

	return &model.GetDashboardResourceResp{
		UserRoles:           roleDTOs,
		AccessibleWidgetIDs: accessibleWidgetIDs,
	}, nil
}
