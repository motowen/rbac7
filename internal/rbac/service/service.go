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

var (
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrConflict         = errors.New("conflict: system owner already exists")
	ErrInvalidNamespace = errors.New("invalid namespace")
	ErrBadRequest       = errors.New("bad request")
)

type RBACService interface {
	AssignSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error
	TransferSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error
	AssignSystemUserRole(ctx context.Context, callerID string, req model.SystemUserRole) error
	DeleteSystemUserRole(ctx context.Context, callerID, namespace, userID string) error
	GetUserRolesMe(ctx context.Context, callerID, scope string) ([]*model.UserRole, error)
	GetUserRoles(ctx context.Context, callerID string, filter model.UserRoleFilter) ([]*model.UserRole, error)
	AssignResourceOwner(ctx context.Context, callerID string, req model.ResourceOwnerUpsertRequest) error
	TransferResourceOwner(ctx context.Context, callerID string, req model.ResourceOwnerUpsertRequest) error
	AssignResourceUserRole(ctx context.Context, callerID string, req model.ResourceUserRole) error
	DeleteResourceUserRole(ctx context.Context, callerID, resourceID, resourceType, userID string) error
}

type Service struct {
	Repo repository.RBACRepository
}

func NewService(repo repository.RBACRepository) *Service {
	return &Service{Repo: repo}
}

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

	// 2b. Validate ownership specifics (Last Owner Check etc happens in Repo usually, but business rule:
	// Transfer usually implies you are GIVING UP ownership to someone else?
	// Existing code checked if `currentOwner.UserID == callerID`.
	// Permission check `platform.system.transfer_owner` on `owner` role effectively covers this
	// IF the user has the 'owner' role on THIS namespace.

	// However, we should verify the system exists and has an owner?
	currentOwner, err := s.Repo.GetSystemOwner(ctx, req.Namespace)
	if err != nil {
		return err
	}
	if currentOwner == nil {
		return errors.New("system not found or has no owner")
	}

	// Double check logic: If I am an Admin (assuming Admin had transfer rights, which they DON'T in this map),
	// I could transfer.
	// Since only Owner has transfer_owner, the HasAnySystemRole check is sufficient.
	// But let's keep the user match for safety if multiple owners allowed?
	// Logic: If I have permission, I can do it.

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
	// Check if role being assigned is valid? (admin, viewer, editor, moderator)
	// User Mapping only has [moderator, owner, admin, dev_user, viewer]
	if req.Role != "admin" && req.Role != "viewer" && req.Role != "dev_user" && req.Role != "moderator" {
		// "editor" was in previous code but not in new mapping. Removing support or keeping for backward compat?
		// User request only defined permissions for [moderator, owner, admin, dev_user, viewer].
		// I'll stick to 'admin', 'viewer', 'dev_user', 'moderator' as valid target roles.
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

func (s *Service) DeleteSystemUserRole(ctx context.Context, callerID, namespace, userID string) error {
	namespace = strings.ToUpper(strings.TrimSpace(namespace))
	userID = strings.TrimSpace(userID)
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

func (s *Service) GetUserRolesMe(ctx context.Context, callerID, scope string) ([]*model.UserRole, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if callerID == "" {
		return nil, ErrUnauthorized
	}

	// Get All My Roles first
	filter := model.UserRoleFilter{UserID: callerID}
	if scope != "" {
		filter.Scope = scope
	}
	roles, err := s.Repo.FindUserRoles(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Permission Check: platform.system.read
	// Requirement: "GetUserRolesMe要檢查有沒有platform.system.read的權限"
	if !CheckRolesHavePermission(roles, PermPlatformSystemRead) {
		return nil, ErrForbidden
	}

	return roles, nil
}

func (s *Service) GetUserRoles(ctx context.Context, callerID string, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	filter.Namespace = strings.ToUpper(strings.TrimSpace(filter.Namespace))
	filter.Role = strings.ToLower(strings.TrimSpace(filter.Role))
	filter.Scope = strings.ToLower(strings.TrimSpace(filter.Scope))
	filter.UserID = strings.TrimSpace(filter.UserID)

	if callerID == "" {
		return nil, ErrUnauthorized
	}

	// Permission Check for List
	if filter.Scope == model.ScopeSystem {
		// Permission: platform.system.get_member
		// Note: User user request 1186: GetUserRoles -> get_meber (get_member)

		canList, err := CheckSystemPermission(ctx, s.Repo, callerID, filter.Namespace, PermPlatformSystemGetMember)
		if err != nil {
			return nil, err
		}
		if !canList {
			return nil, ErrForbidden
		}
	}

	return s.Repo.FindUserRoles(ctx, filter)
}

func (s *Service) validateRequest(callerID string, req model.SystemOwnerUpsertRequest) error {
	if err := s.validateCallerAndNamespace(callerID, req.Namespace); err != nil {
		return err
	}
	if req.UserID == "" {
		return ErrBadRequest
	}
	return nil
}

func (s *Service) validateCallerAndNamespace(callerID, namespace string) error {
	if callerID == "" {
		return ErrUnauthorized
	}
	if namespace == "" {
		return ErrInvalidNamespace
	}
	return nil
}

// --- Resource Role Management ---

func (s *Service) AssignResourceOwner(ctx context.Context, callerID string, req model.ResourceOwnerUpsertRequest) error {
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	req.ResourceType = strings.ToLower(strings.TrimSpace(req.ResourceType))

	if callerID == "" {
		return ErrUnauthorized
	}
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

func (s *Service) TransferResourceOwner(ctx context.Context, callerID string, req model.ResourceOwnerUpsertRequest) error {
	req.UserID = strings.TrimSpace(req.UserID)
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	req.ResourceType = strings.ToLower(strings.TrimSpace(req.ResourceType))

	if callerID == "" {
		return ErrUnauthorized
	}
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

func (s *Service) AssignResourceUserRole(ctx context.Context, callerID string, req model.ResourceUserRole) error {
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	req.UserType = strings.ToLower(strings.TrimSpace(req.UserType))
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	req.ResourceType = strings.ToLower(strings.TrimSpace(req.ResourceType))
	req.UserID = strings.TrimSpace(req.UserID)

	if callerID == "" {
		return ErrUnauthorized
	}
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

	// Permission: resource.{type}.add_member
	perm := "resource." + req.ResourceType + ".add_member"
	// No namespace
	canAssign, err := CheckResourcePermission(ctx, s.Repo, callerID, req.ResourceID, req.ResourceType, perm)
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

func (s *Service) DeleteResourceUserRole(ctx context.Context, callerID, resourceID, resourceType, userID string) error {
	userID = strings.TrimSpace(userID)
	resourceID = strings.TrimSpace(resourceID)
	resourceType = strings.ToLower(strings.TrimSpace(resourceType))

	if callerID == "" {
		return ErrUnauthorized
	}
	if userID == "" || resourceID == "" || resourceType == "" {
		return ErrBadRequest
	}

	// Permission: resource.{type}.remove_member
	perm := "resource." + resourceType + ".remove_member"
	// No Namespace
	canDelete, err := CheckResourcePermission(ctx, s.Repo, callerID, resourceID, resourceType, perm)
	if err != nil {
		return err
	}
	if !canDelete {
		return ErrForbidden
	}

	// Cannot remove Owner
	isOwner, err := s.Repo.HasResourceRole(ctx, userID, resourceID, resourceType, model.RoleResourceOwner)
	if err != nil {
		return err
	}
	if isOwner {
		return ErrForbidden // Cannot remove owner
	}

	err = s.Repo.DeleteUserRole(ctx, "", userID, model.ScopeResource, resourceID, resourceType, callerID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	log.Printf("Audit: Resource User Role Deleted. Caller=%s, Target=%s, Resource=%s:%s", callerID, userID, resourceType, resourceID)
	return nil
}
