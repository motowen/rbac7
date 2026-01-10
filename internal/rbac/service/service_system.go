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

func (s *Service) AssignSystemOwner(ctx context.Context, callerID string, req model.AssignSystemOwnerReq) error {
	// Check permissions: Caller must have 'platform.system.add_owner'
	hasPerm, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:  callerID,
		Entity:    "system",
		Operation: "assign_owner",
	})
	if err != nil {
		return err
	}
	if !hasPerm {
		return ErrForbidden
	}

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

func (s *Service) TransferSystemOwner(ctx context.Context, callerID string, req model.TransferSystemOwnerReq) error {
	// Cannot transfer to self
	if req.UserID == callerID {
		return ErrBadRequest
	}

	// 2. Check permissions: Caller must have 'platform.system.transfer_owner'
	hasPerm, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:  callerID,
		Entity:    "system",
		Operation: "transfer_owner",
		Namespace: req.Namespace,
	})
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

func (s *Service) AssignSystemUserRole(ctx context.Context, callerID string, req model.AssignSystemUserRoleReq) error {
	if req.Role == model.RoleSystemOwner {
		return ErrForbidden
	}
	// Check if role being assigned is valid? (admin, viewer, dev_user, moderator)
	if req.Role != "admin" && req.Role != "viewer" && req.Role != "dev_user" && req.Role != "moderator" {
		return ErrBadRequest
	}

	// Permission: platform.system.add_member
	canAssign, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:  callerID,
		Entity:    "system",
		Operation: "assign_user_role",
		Namespace: req.Namespace,
	})
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

func (s *Service) AssignSystemUserRoles(ctx context.Context, callerID string, req model.AssignSystemUserRolesReq) (*model.BatchUpsertResult, error) {
	// Note: Scope is implied to be System

	// Permission: platform.system.add_member
	canAssign, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:  callerID,
		Entity:    "system",
		Operation: "assign_user_roles_batch",
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
	for _, userID := range req.UserIDs {
		userType := req.UserType
		if userType == "" {
			userType = model.UserTypeMember
		}
		role := &model.UserRole{
			UserID:    userID,
			Role:      req.Role,
			Scope:     model.ScopeSystem,
			Namespace: req.Namespace,
			UserType:  userType,
			CreatedBy: callerID,
			UpdatedBy: callerID,
		}
		roles = append(roles, role)
	}

	result, err := s.Repo.BulkUpsertUserRoles(ctx, roles)
	if err != nil {
		return nil, err
	}

	log.Printf("Audit: System User Roles Assigned (Batch). Caller=%s, Success=%d, Failed=%d, Role=%s, Namespace=%s",
		callerID, result.SuccessCount, result.FailedCount, req.Role, req.Namespace)

	return result, nil
}

func (s *Service) DeleteSystemUserRole(ctx context.Context, callerID string, req model.DeleteSystemUserRoleReq) error {
	// Permission: platform.system.remove_member
	canDelete, err := s.Policy.CheckOperationPermission(ctx, s.Repo, policy.OperationRequest{
		CallerID:  callerID,
		Entity:    "system",
		Operation: "delete_user_role",
		Namespace: req.Namespace,
	})
	if err != nil {
		return err
	}
	if !canDelete {
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

	err = s.Repo.DeleteUserRole(ctx, req.Namespace, req.UserID, model.ScopeSystem, "", "", callerID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	log.Printf("Audit: System User Role Deleted. Caller=%s, Target=%s, Namespace=%s", callerID, req.UserID, req.Namespace)
	return nil
}
