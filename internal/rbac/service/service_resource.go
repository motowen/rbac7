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
	// Permission check handled by RBAC middleware (check_scope: none)

	// Check if owner already exists
	count, err := s.Repo.CountResourceOwners(ctx, req.ResourceID, req.ResourceType)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrConflict
	}

	newRole := &model.UserRole{
		UserID:       callerID, // Caller becomes owner
		Role:         model.RoleResourceOwner,
		Scope:        model.ScopeResource,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		UserType:     model.UserTypeMember,
		CreatedBy:    callerID,
		UpdatedBy:    callerID,
	}

	err = s.Repo.CreateUserRole(ctx, newRole)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return ErrConflict
		}
		return err
	}

	log.Printf("Audit: Resource Owner Assigned. Caller=%s, Target=%s, Resource=%s:%s", callerID, callerID, req.ResourceType, req.ResourceID)

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation:    "assign_owner",
		CallerID:     callerID,
		Scope:        model.ScopeResource,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		UserID:       callerID,
	})

	return nil
}

func (s *Service) TransferResourceOwner(ctx context.Context, callerID string, req model.TransferResourceOwnerReq) error {
	if req.UserID == callerID {
		return ErrBadRequest
	}

	// Permission check handled by RBAC middleware

	oldOwnerID := callerID

	err := s.Repo.TransferResourceOwner(ctx, req.ResourceID, req.ResourceType, oldOwnerID, req.UserID, callerID)
	if err != nil {
		return err
	}

	log.Printf("Audit: Resource Owner Transferred. Caller=%s, NewOwner=%s, OldOwner=%s, Resource=%s:%s", callerID, req.UserID, oldOwnerID, req.ResourceType, req.ResourceID)

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation:    "transfer_owner",
		CallerID:     callerID,
		Scope:        model.ScopeResource,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		NewOwnerID:   req.UserID,
	})

	return nil
}

func (s *Service) AssignResourceUserRole(ctx context.Context, callerID string, req model.AssignResourceUserRoleReq) error {
	if req.Role == model.RoleResourceOwner {
		return ErrForbidden // Use Transfer or AssignOwner
	}
	if req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		return ErrBadRequest
	}

	// Permission check handled by RBAC middleware

	// Check if target user is already owner
	isOwner, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		return ErrForbidden
	}

	// For dashboard_widget: target user must have parent dashboard read permission
	if req.ResourceType == model.ResourceTypeDashboardWidget {
		viewerRoles := s.Policy.GetRolesWithPermission(model.PermResourceDashboardRead, false)
		hasParentAccess, err := s.Repo.HasAnyResourceRole(ctx, req.UserID, req.ParentResourceID, model.ResourceTypeDashboard, viewerRoles)
		if err != nil {
			return err
		}
		if !hasParentAccess {
			return ErrBadRequest // User must have parent dashboard read permission to be added to widget whitelist
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
		CreatedBy:        callerID,
		UpdatedBy:        callerID,
	}
	if role.UserType == "" {
		role.UserType = model.UserTypeMember
	}
	if err := s.Repo.UpsertUserRole(ctx, role); err != nil {
		return err
	}

	log.Printf("Audit: Resource User Role Assigned. Caller=%s, Target=%s, Role=%s, Resource=%s:%s", callerID, req.UserID, req.Role, req.ResourceType, req.ResourceID)

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation:        "assign_user_role",
		CallerID:         callerID,
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
	if req.UserID == "" || req.ResourceID == "" || req.ResourceType == "" {
		return ErrBadRequest
	}

	// Permission check handled by RBAC middleware

	// Cannot remove Owner
	isOwner, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		return ErrForbidden
	}

	err = s.Repo.DeleteUserRole(ctx, req.Namespace, req.UserID, model.ScopeResource, req.ResourceID, req.ResourceType, req.ParentResourceID, callerID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	log.Printf("Audit: Resource User Role Deleted. Caller=%s, Target=%s, Resource=%s:%s", callerID, req.UserID, req.ResourceType, req.ResourceID)

	// For dashboard: cascade delete user's child widget whitelist roles
	if req.ResourceType == model.ResourceTypeDashboard {
		// Ignore errors - this is a best-effort cleanup
		_ = s.Repo.DeleteUserRolesByParent(ctx, req.UserID, req.ResourceID, model.ResourceTypeDashboardWidget, callerID)
	}

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation:        "delete_user_role",
		CallerID:         callerID,
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
	// Permission check handled by RBAC middleware

	// For dashboard_widget: filter users who have parent dashboard read permission
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
		// If no valid users, return early with failure result
		if len(validUserIDs) == 0 {
			return &model.BatchUpsertResult{
				SuccessCount: 0,
				FailedCount:  len(invalidUsers),
				FailedUsers:  invalidUsers,
			}, nil
		}
	}

	// Build roles slice for bulk upsert
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
			CreatedBy:        callerID,
			UpdatedBy:        callerID,
		}
		roles = append(roles, role)
	}

	result, err := s.Repo.BulkUpsertUserRoles(ctx, roles)
	if err != nil {
		return nil, err
	}

	// Merge invalid users (no parent permission) into result
	if len(invalidUsers) > 0 {
		result.FailedCount += len(invalidUsers)
		result.FailedUsers = append(result.FailedUsers, invalidUsers...)
	}

	log.Printf("Audit: Resource User Roles Assigned (Batch). Caller=%s, Success=%d, Failed=%d, Role=%s, Resource=%s:%s",
		callerID, result.SuccessCount, result.FailedCount, req.Role, req.ResourceType, req.ResourceID)

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation:        "assign_user_roles_batch",
		CallerID:         callerID,
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

// SoftDeleteResource - Soft delete all user roles for a resource
// This is used when deleting a resource entirely (dashboard, dashboard_widget, library_widget)
func (s *Service) SoftDeleteResource(ctx context.Context, callerID string, req *model.SoftDeleteResourceReq) error {
	// Permission check handled by RBAC middleware

	if err := s.Repo.SoftDeleteResourceUserRoles(ctx, req, callerID); err != nil {
		return err
	}

	log.Printf("Audit: Resource Soft Deleted. Caller=%s, Resource=%s:%s, ChildResources=%d",
		callerID, req.ResourceType, req.ResourceID, len(req.ChildResourceIDs))

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation:        "delete_resource",
		CallerID:         callerID,
		Scope:            model.ScopeResource,
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		ChildResourceIDs: req.ChildResourceIDs,
	})

	return nil
}

// GetDashboardResource - Get dashboard user roles and accessible widget IDs
// Permission check is handled by RBAC middleware (resource.dashboard.read)
// For each widget, check if caller can access:
// - Inheritance mode (0 roles): inherit from parent dashboard -> accessible
// - Whitelist mode (>0 roles): strict check on widget -> accessible only if caller has role
func (s *Service) GetDashboardResource(ctx context.Context, callerID string, req model.GetDashboardResourceReq) (*model.GetDashboardResourceResp, error) {
	// Get dashboard user roles
	filter := model.UserRoleFilter{
		UserID:       callerID,
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		Scope:        model.ScopeResource,
	}
	userRoles, err := s.Repo.FindUserRoles(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Convert to DTO
	roleDTOs := make([]*model.UserRoleDTO, 0, len(userRoles))
	for _, role := range userRoles {
		roleDTOs = append(roleDTOs, &model.UserRoleDTO{
			UserID:   role.UserID,
			UserType: role.UserType,
			Role:     role.Role,
		})
	}

	// Determine accessible widget IDs
	accessibleWidgetIDs := make([]string, 0)
	viewerRoles := s.Policy.GetRolesWithPermission(model.PermResourceDashboardWidgetRead, false)

	for _, widgetID := range req.ChildResourceIDs {
		// Check if widget is in whitelist mode (has roles assigned)
		roleCount, err := s.Repo.CountResourceRoles(ctx, widgetID, "dashboard_widget")
		if err != nil {
			return nil, err
		}

		if roleCount == 0 {
			// Inheritance mode: inherit from parent dashboard -> accessible
			accessibleWidgetIDs = append(accessibleWidgetIDs, widgetID)
		} else {
			// Whitelist mode: strict check on widget
			hasRole, err := s.Repo.HasAnyResourceRole(ctx, callerID, widgetID, "dashboard_widget", viewerRoles)
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
