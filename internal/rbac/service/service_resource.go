package service

import (
	"context"
	"errors"
	"log"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"

	"go.mongodb.org/mongo-driver/mongo"
)

func (s *Service) AssignResourceOwner(ctx context.Context, callerID string, req model.AssignResourceOwnerReq) error {
	if req.ResourceID == "" || req.ResourceType == "" {
		return ErrBadRequest
	}

	// Permission: None required for AssignResourceOwner as per requirements.
	// Namespace: None required.
	// UserID: Auto-assigned to Caller.

	// Check if owner already exists
	count, err := s.Repo.CountResourceOwners(ctx, req.ResourceID, req.ResourceType)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrConflict
	}

	// 1. Create new UserRole
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
			// If duplicate, it means owner already exists?
			// The index (scope, ns, resID, resType, role=owner) is unique.
			// So if we try to assign owner and one exists, we get duplicate.
			// Requirement: "一個資源只能有一個Owner"
			return ErrConflict // "resource owner already exists"
		}
		return err
	}

	log.Printf("Audit: Resource Owner Assigned. Caller=%s, Target=%s, Resource=%s:%s", callerID, callerID, req.ResourceType, req.ResourceID)
	return nil
}

func (s *Service) TransferResourceOwner(ctx context.Context, callerID string, req model.TransferResourceOwnerReq) error {
	if req.UserID == "" || req.ResourceID == "" || req.ResourceType == "" {
		return ErrBadRequest
	}
	if req.UserID == callerID {
		return ErrBadRequest
	}

	// Permission: resource.dashboard.transfer_owner (or generic resource.transfer_owner)
	hasPerm, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:     callerID,
		Entity:       req.ResourceType,
		Operation:    "transfer_owner",
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
	})
	if err != nil {
		return err
	}
	if !hasPerm {
		return ErrForbidden
	}

	// Old Owner = Caller (Simplification)
	oldOwnerID := callerID

	// Namespace is empty string
	err = s.Repo.TransferResourceOwner(ctx, req.ResourceID, req.ResourceType, oldOwnerID, req.UserID, callerID)
	if err != nil {
		return err
	}

	log.Printf("Audit: Resource Owner Transferred. Caller=%s, NewOwner=%s, OldOwner=%s, Resource=%s:%s", callerID, req.UserID, oldOwnerID, req.ResourceType, req.ResourceID)
	return nil
}

func (s *Service) AssignResourceUserRole(ctx context.Context, callerID string, req model.AssignResourceUserRoleReq) error {
	// Scope implied Resource

	if req.UserID == "" || req.ResourceID == "" || req.ResourceType == "" {
		return ErrBadRequest
	}
	if req.Role == model.RoleResourceOwner {
		return ErrForbidden // Use Transfer or AssignOwner
	}
	// Validate Role? (admin, editor, viewer)
	if req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		return ErrBadRequest
	}

	// Permission Check using PolicyEngine (auto-detects widget viewer operations via Role)
	canAssign, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:         callerID,
		Operation:        "assign_user_role",
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		Role:             req.Role,
	})
	if err != nil {
		return err
	}
	if !canAssign {
		return ErrForbidden
	}

	// Prevent adding duplicate owner? ALready checked Role != Owner.
	// Check if target user is ALREADY owner?
	isOwner, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		// Cannot change Owner's role via Assign. Must Transfer.
		return ErrForbidden
	}

	role := &model.UserRole{
		UserID:       req.UserID,
		Role:         req.Role,
		Scope:        model.ScopeResource,
		Namespace:    "", // No namespace
		ResourceID:   req.ResourceID,
		ResourceType: req.ResourceType,
		UserType:     req.UserType,
		CreatedBy:    callerID,
		UpdatedBy:    callerID,
	}
	if role.UserType == "" {
		role.UserType = model.UserTypeMember
	}
	if err := s.Repo.UpsertUserRole(ctx, role); err != nil {
		return err
	}

	log.Printf("Audit: Resource User Role Assigned. Caller=%s, Target=%s, Role=%s, Resource=%s:%s", callerID, req.UserID, req.Role, req.ResourceType, req.ResourceID)
	return nil
}

func (s *Service) DeleteResourceUserRole(ctx context.Context, callerID string, req model.DeleteResourceUserRoleReq) error {
	if req.UserID == "" || req.ResourceID == "" || req.ResourceType == "" {
		return ErrBadRequest
	}

	// For widget, determine target role for proper permission check
	var targetRole string
	if req.ResourceType == model.ResourceTypeWidget {
		isViewer, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceViewer)
		if err != nil {
			return err
		}
		if isViewer {
			targetRole = model.RoleResourceViewer
		}
	}

	// Permission Check using PolicyEngine (auto-detects widget viewer operations via Role)
	canDelete, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:         callerID,
		Operation:        "delete_user_role",
		ResourceID:       req.ResourceID,
		ResourceType:     req.ResourceType,
		ParentResourceID: req.ParentResourceID,
		Role:             targetRole,
	})
	if err != nil {
		return err
	}
	if !canDelete {
		return ErrForbidden
	}

	// Cannot remove Owner
	isOwner, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		return ErrForbidden // Cannot remove owner
	}

	err = s.Repo.DeleteUserRole(ctx, "", req.UserID, model.ScopeResource, req.ResourceID, req.ResourceType, callerID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	log.Printf("Audit: Resource User Role Deleted. Caller=%s, Target=%s, Resource=%s:%s", callerID, req.UserID, req.ResourceType, req.ResourceID)
	return nil
}

func (s *Service) AssignResourceUserRoles(ctx context.Context, callerID string, req model.AssignResourceUserRolesReq) (*model.BatchUpsertResult, error) {
	// Permission Check using PolicyEngine
	var opReq policy.OperationRequest
	if req.ResourceType == model.ResourceTypeWidget && req.Role == model.RoleResourceViewer {
		opReq = policy.OperationRequest{
			CallerID:         callerID,
			Entity:           "dashboard_widget",
			Operation:        "assign_user_roles_batch",
			ResourceID:       req.ResourceID,
			ResourceType:     req.ResourceType,
			ParentResourceID: req.ParentResourceID,
		}
	} else {
		opReq = policy.OperationRequest{
			CallerID:     callerID,
			Entity:       req.ResourceType,
			Operation:    "assign_user_roles_batch",
			ResourceID:   req.ResourceID,
			ResourceType: req.ResourceType,
		}
	}

	canAssign, err := s.Policy.CheckOperationPermission(ctx, s.Repo, opReq)
	if err != nil {
		return nil, err
	}
	if !canAssign {
		return nil, ErrForbidden
	}

	// Build roles slice for bulk upsert
	var roles []*model.UserRole
	userType := req.UserType
	if userType == "" {
		userType = model.UserTypeMember
	}
	for _, userID := range req.UserIDs {
		role := &model.UserRole{
			UserID:       userID,
			Role:         req.Role,
			Scope:        model.ScopeResource,
			Namespace:    "",
			ResourceID:   req.ResourceID,
			ResourceType: req.ResourceType,
			UserType:     userType,
			CreatedBy:    callerID,
			UpdatedBy:    callerID,
		}
		roles = append(roles, role)
	}

	result, err := s.Repo.BulkUpsertUserRoles(ctx, roles)
	if err != nil {
		return nil, err
	}

	log.Printf("Audit: Resource User Roles Assigned (Batch). Caller=%s, Success=%d, Failed=%d, Role=%s, Resource=%s:%s",
		callerID, result.SuccessCount, result.FailedCount, req.Role, req.ResourceType, req.ResourceID)

	return result, nil
}

// AssignLibraryWidgetViewers - Batch assign viewers to a library_widget
// Permission: platform.system.add_member in namespace
func (s *Service) AssignLibraryWidgetViewers(ctx context.Context, callerID string, req model.AssignLibraryWidgetViewersReq) (*model.BatchUpsertResult, error) {
	// Permission Check: Caller needs platform.system.add_member in this namespace
	canAssign, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:  callerID,
		Entity:    "library_widget",
		Operation: "assign_viewers_batch",
		Namespace: req.Namespace,
	})
	if err != nil {
		return nil, err
	}
	if !canAssign {
		return nil, ErrForbidden
	}

	// Build roles slice for bulk upsert
	var roles []*model.UserRole
	userType := req.UserType
	if userType == "" {
		userType = model.UserTypeMember
	}

	for _, userID := range req.UserIDs {
		role := &model.UserRole{
			UserID:       userID,
			Role:         model.RoleResourceViewer,
			Scope:        model.ScopeResource,
			Namespace:    req.Namespace,
			ResourceID:   req.ResourceID,
			ResourceType: model.ResourceTypeLibraryWidget,
			UserType:     userType,
			CreatedBy:    callerID,
			UpdatedBy:    callerID,
		}
		roles = append(roles, role)
	}

	result, err := s.Repo.BulkUpsertUserRoles(ctx, roles)
	if err != nil {
		return nil, err
	}

	log.Printf("Audit: Library Widget Viewers Assigned (Batch). Caller=%s, Success=%d, Failed=%d, Widget=%s, Namespace=%s",
		callerID, result.SuccessCount, result.FailedCount, req.ResourceID, req.Namespace)

	return result, nil
}

// DeleteLibraryWidgetViewer - Remove a viewer from a library_widget
// Permission: platform.system.remove_member in namespace
func (s *Service) DeleteLibraryWidgetViewer(ctx context.Context, callerID string, req model.DeleteLibraryWidgetViewerReq) error {
	// Permission Check: Caller needs platform.system.remove_member in this namespace
	canRemove, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:  callerID,
		Entity:    "library_widget",
		Operation: "delete_viewer",
		Namespace: req.Namespace,
	})
	if err != nil {
		return err
	}
	if !canRemove {
		return ErrForbidden
	}

	err = s.Repo.DeleteUserRole(ctx, req.Namespace, req.UserID, model.ScopeResource,
		req.ResourceID, model.ResourceTypeLibraryWidget, callerID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil // Idempotent: already removed
		}
		return err
	}

	log.Printf("Audit: Library Widget Viewer Deleted. Caller=%s, Target=%s, Widget=%s, Namespace=%s",
		callerID, req.UserID, req.ResourceID, req.Namespace)

	return nil
}
