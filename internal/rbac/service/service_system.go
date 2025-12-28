package service

import (
	"context"
	"errors"
	"log"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
	"strings"

	"go.mongodb.org/mongo-driver/mongo"
)

func (s *Service) AssignSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error {
	// Normalize input: Trim Space then format
	req.Namespace = strings.ToUpper(strings.TrimSpace(req.Namespace))
	req.UserID = strings.TrimSpace(req.UserID)
	// 0. Validate Caller & Input
	if err := s.validateRequest(callerID, req); err != nil {
		return err
	}

	// 2. Check permissions: Caller must have 'platform.system.add_owner'
	// Usually moderator is global, so namespace might be empty string?
	hasPerm, err := CheckSystemPermission(ctx, s.Repo, callerID, "", PermPlatformSystemAddOwner)
	if err != nil {
		return err
	}
	if !hasPerm {
		return ErrForbidden
	}

	// 3. Create new UserRole
	newRole := &model.UserRole{
		UserID:    req.UserID,
		Role:      model.RoleSystemOwner,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserType:  model.UserTypeMember, // Defaulting to member as per likely requirement
		CreatedBy: callerID,             // Audit
		UpdatedBy: callerID,
	}

	err = s.Repo.CreateUserRole(ctx, newRole)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return ErrConflict
		}
		return err
	}

	log.Printf("Audit: System Owner Assigned. Caller=%s, Target=%s, Namespace=%s", callerID, req.UserID, req.Namespace)

	return nil
}

func (s *Service) TransferSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error {
	req.Namespace = strings.ToUpper(strings.TrimSpace(req.Namespace))
	req.UserID = strings.TrimSpace(req.UserID)
	// 0. Validate Caller & Input
	if err := s.validateRequest(callerID, req); err != nil {
		return err
	}
	// Cannot transfer to self
	if req.UserID == callerID {
		return ErrBadRequest
	}

	// 2. Check permissions: Caller must have 'platform.system.transfer_owner'
	hasPerm, err := CheckSystemPermission(ctx, s.Repo, callerID, req.Namespace, PermPlatformSystemTransferOwner)
	if err != nil {
		return err
	}
	if !hasPerm {
		return ErrForbidden
	}

	// 2b. Validate ownership specifics
	currentOwner, err := s.Repo.GetSystemOwner(ctx, req.Namespace)
	if err != nil {
		return err
	}
	if currentOwner == nil {
		return errors.New("system not found or has no owner")
	}

	// 3. Perform Transfer (Transaction)
	// New owner is req.UserID
	err = s.Repo.TransferSystemOwner(ctx, req.Namespace, callerID, req.UserID, callerID)
	if err != nil {
		// Map errors if needed, or return generic
		return err
	}

	log.Printf("Audit: System Owner Transferred. Caller=%s, NewOwner=%s, OldOwner=%s, Namespace=%s", callerID, req.UserID, callerID, req.Namespace)

	return nil
}

func (s *Service) AssignSystemUserRole(ctx context.Context, callerID string, req model.SystemUserRole) error {
	req.Namespace = strings.ToUpper(strings.TrimSpace(req.Namespace))
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	req.UserType = strings.ToLower(strings.TrimSpace(req.UserType))
	req.Scope = strings.ToLower(strings.TrimSpace(req.Scope))
	req.UserID = strings.TrimSpace(req.UserID)

	if err := s.validateCallerAndNamespace(callerID, req.Namespace); err != nil {
		return err
	}
	if req.UserID == "" {
		return ErrBadRequest
	}
	if req.Role == model.RoleSystemOwner {
		return ErrForbidden
	}
	// Check if role being assigned is valid? (admin, viewer, dev_user, moderator)
	if req.Role != "admin" && req.Role != "viewer" && req.Role != "dev_user" && req.Role != "moderator" {
		return ErrBadRequest
	}

	// Permission: platform.system.add_member
	canAssign, err := CheckSystemPermission(ctx, s.Repo, callerID, req.Namespace, PermPlatformSystemAddMember)
	if err != nil {
		return err
	}
	if !canAssign {
		return ErrForbidden
	}

	currentOwner, err := s.Repo.GetSystemOwner(ctx, req.Namespace)
	if err != nil {
		return err
	}
	if currentOwner != nil && currentOwner.UserID == req.UserID {
		count, err := s.Repo.CountSystemOwners(ctx, req.Namespace)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrForbidden
		}
	}

	role := &model.UserRole{
		UserID:    req.UserID,
		Role:      req.Role,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserType:  req.UserType,
		CreatedBy: callerID,
		UpdatedBy: callerID,
	}
	if role.UserType == "" {
		role.UserType = model.UserTypeMember
	}
	if err := s.Repo.UpsertUserRole(ctx, role); err != nil {
		return err
	}

	log.Printf("Audit: System User Role Assigned. Caller=%s, Target=%s, Role=%s, Namespace=%s", callerID, req.UserID, req.Role, req.Namespace)
	return nil
}

func (s *Service) DeleteSystemUserRole(ctx context.Context, callerID string, req model.DeleteSystemUserRoleReq) error {
	namespace := strings.ToUpper(strings.TrimSpace(req.Namespace))
	userID := strings.TrimSpace(req.UserID)

	if err := s.validateCallerAndNamespace(callerID, namespace); err != nil {
		return err
	}
	if userID == "" {
		return ErrBadRequest
	}

	// Permission: platform.system.remove_member
	canDelete, err := CheckSystemPermission(ctx, s.Repo, callerID, namespace, PermPlatformSystemRemoveMember)
	if err != nil {
		return err
	}
	if !canDelete {
		return ErrForbidden
	}

	currentOwner, err := s.Repo.GetSystemOwner(ctx, namespace)
	if err != nil {
		return err
	}
	if currentOwner != nil && currentOwner.UserID == userID {
		count, err := s.Repo.CountSystemOwners(ctx, namespace)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrForbidden
		}
	}

	err = s.Repo.DeleteUserRole(ctx, namespace, userID, model.ScopeSystem, "", "", callerID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	log.Printf("Audit: System User Role Deleted. Caller=%s, Target=%s, Namespace=%s", callerID, userID, namespace)
	return nil
}
