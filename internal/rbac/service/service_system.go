package service

import (
	"context"
	"errors"
	"log"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"

	"go.mongodb.org/mongo-driver/mongo"
)

func (s *Service) AssignSystemOwner(ctx context.Context, callerID string, req model.AssignSystemOwnerReq) error {
	// Permission check handled by RBAC middleware

	newRole := &model.UserRole{
		UserID:    req.UserID,
		Role:      model.RoleSystemOwner,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserType:  model.UserTypeMember,
		CreatedBy: callerID,
		UpdatedBy: callerID,
	}

	err := s.Repo.CreateUserRole(ctx, newRole)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return ErrConflict
		}
		return err
	}

	log.Printf("Audit: System Owner Assigned. Caller=%s, Target=%s, Namespace=%s", callerID, req.UserID, req.Namespace)

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation: "assign_owner",
		CallerID:  callerID,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserID:    req.UserID,
	})

	return nil
}

func (s *Service) TransferSystemOwner(ctx context.Context, callerID string, req model.TransferSystemOwnerReq) error {
	// Cannot transfer to self
	if req.UserID == callerID {
		return ErrBadRequest
	}

	// Permission check handled by RBAC middleware

	// Validate ownership specifics
	currentOwner, err := s.Repo.GetSystemOwner(ctx, req.Namespace)
	if err != nil {
		return err
	}
	if currentOwner == nil {
		return errors.New("system not found or has no owner")
	}

	// Perform Transfer (Transaction)
	err = s.Repo.TransferSystemOwner(ctx, req.Namespace, callerID, req.UserID, callerID)
	if err != nil {
		return err
	}

	log.Printf("Audit: System Owner Transferred. Caller=%s, NewOwner=%s, OldOwner=%s, Namespace=%s", callerID, req.UserID, callerID, req.Namespace)

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation:  "transfer_owner",
		CallerID:   callerID,
		Scope:      model.ScopeSystem,
		Namespace:  req.Namespace,
		NewOwnerID: req.UserID,
	})

	return nil
}

func (s *Service) AssignSystemUserRole(ctx context.Context, callerID string, req model.AssignSystemUserRoleReq) error {
	if req.Role == model.RoleSystemOwner {
		return ErrForbidden
	}
	// Check if role being assigned is valid
	if req.Role != "admin" && req.Role != "viewer" && req.Role != "dev_user" && req.Role != "moderator" {
		return ErrBadRequest
	}

	// Permission check handled by RBAC middleware

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

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation: "assign_user_role",
		CallerID:  callerID,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserID:    req.UserID,
		UserType:  req.UserType,
		Role:      req.Role,
	})

	return nil
}

func (s *Service) AssignSystemUserRoles(ctx context.Context, callerID string, req model.AssignSystemUserRolesReq) (*model.BatchUpsertResult, error) {
	// Permission check handled by RBAC middleware

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

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation: "assign_user_roles_batch",
		CallerID:  callerID,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserIDs:   req.UserIDs,
		UserType:  req.UserType,
		Role:      req.Role,
	})

	return result, nil
}

func (s *Service) DeleteSystemUserRole(ctx context.Context, callerID string, req model.DeleteSystemUserRoleReq) error {
	// Permission check handled by RBAC middleware

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

	// Record history
	s.recordHistory(&model.UserRoleHistory{
		Operation: "delete_user_role",
		CallerID:  callerID,
		Scope:     model.ScopeSystem,
		Namespace: req.Namespace,
		UserID:    req.UserID,
		UserType:  req.UserType,
	})

	return nil
}
