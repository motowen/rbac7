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

	role := &model.UserRole{
		UserID:       req.UserID,
		Role:         req.Role,
		Scope:        model.ScopeResource,
		Namespace:    "",
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

	// Permission check handled by RBAC middleware

	// Cannot remove Owner
	isOwner, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		return ErrForbidden
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
	// Permission check handled by RBAC middleware

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
func (s *Service) AssignLibraryWidgetViewers(ctx context.Context, callerID string, req model.AssignLibraryWidgetViewersReq) (*model.BatchUpsertResult, error) {
	// Permission check handled by RBAC middleware

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
func (s *Service) DeleteLibraryWidgetViewer(ctx context.Context, callerID string, req model.DeleteLibraryWidgetViewerReq) error {
	// Permission check handled by RBAC middleware

	err := s.Repo.DeleteUserRole(ctx, req.Namespace, req.UserID, model.ScopeResource,
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

// SoftDeleteResource - Soft delete all user roles for a resource
// This is used when deleting a resource entirely (dashboard, dashboard_widget, library_widget)
func (s *Service) SoftDeleteResource(ctx context.Context, callerID string, req model.SoftDeleteResourceReq) error {
	// Permission check handled by RBAC middleware

	if err := s.Repo.SoftDeleteResourceUserRoles(ctx, req, callerID); err != nil {
		return err
	}

	log.Printf("Audit: Resource Soft Deleted. Caller=%s, Resource=%s:%s, ChildResources=%d",
		callerID, req.ResourceType, req.ResourceID, len(req.ChildResourceIDs))

	return nil
}
