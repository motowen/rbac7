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
	perm := "resource." + req.ResourceType + ".transfer_owner"

	// No namespace
	hasPerm, err := CheckResourcePermission(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, perm)
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

	// Permission Check
	var perm string
	targetResourceID := req.ResourceID
	targetResourceType := req.ResourceType

	if req.ResourceType == model.ResourceTypeWidget && req.Role == model.RoleResourceViewer {
		// Specific permission for adding widget viewer
		perm = model.PermResourceDashboardAddWidgetViewer
		// Check on Parent Dashboard
		if req.ParentResourceID != "" {
			targetResourceID = req.ParentResourceID
			targetResourceType = model.ResourceTypeDashboard
		}
	} else {
		// Generic permission: resource.{type}.add_member
		perm = "resource." + req.ResourceType + ".add_member"
	}

	// No namespace
	canAssign, err := CheckResourcePermission(ctx, s.Repo, callerID, targetResourceID, targetResourceType, perm)
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

	// Determine Permission based on Target Role & Resource Type
	perm := "resource." + req.ResourceType + ".remove_member"
	targetResourceID := req.ResourceID
	targetResourceType := req.ResourceType

	if req.ResourceType == model.ResourceTypeWidget {
		// Specific check for Widget Viewer removal
		// check target role...
		isViewer, err := s.Repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, model.RoleResourceViewer)
		if err != nil {
			return err
		}
		if isViewer {
			perm = model.PermResourceDashboardAddWidgetViewer
			// Check on Parent Dashboard
			if req.ParentResourceID != "" {
				targetResourceID = req.ParentResourceID
				targetResourceType = model.ResourceTypeDashboard
			}
		}
	}

	// No Namespace
	canDelete, err := CheckResourcePermission(ctx, s.Repo, callerID, targetResourceID, targetResourceType, perm)
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
