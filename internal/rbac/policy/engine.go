package policy

import (
	"context"
	"fmt"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
	"sort"
)

// Engine is the central policy engine for permission checking
type Engine struct {
	entityPolicies    map[string]*EntityPolicy
	checkPermConfig   *CheckPermissionConfig
	systemRolePerms   map[string][]string
	resourceRolePerms map[string][]string
}

// NewEngine creates a new PolicyEngine instance
func NewEngine() (*Engine, error) {
	loader := NewLoader()

	entityPolicies, err := loader.LoadEntityPolicies()
	if err != nil {
		return nil, fmt.Errorf("failed to load entity policies: %w", err)
	}

	checkPermConfig, err := loader.LoadCheckPermissionConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load check permission config: %w", err)
	}

	// Load role permissions from JSON files
	systemRolePerms, err := loader.LoadSystemRolePermissions()
	if err != nil {
		return nil, fmt.Errorf("failed to load system role permissions: %w", err)
	}

	resourceRolePerms, err := loader.LoadResourceRolePermissions()
	if err != nil {
		return nil, fmt.Errorf("failed to load resource role permissions: %w", err)
	}

	engine := &Engine{
		entityPolicies:    entityPolicies,
		checkPermConfig:   checkPermConfig,
		systemRolePerms:   systemRolePerms,
		resourceRolePerms: resourceRolePerms,
	}

	return engine, nil
}

// normalizeRequest auto-infers Entity from Scope/ResourceType and adjusts Operation for special cases
// For dashboard_widget with viewer role, it uses viewer-specific operations (assign_viewer, delete_viewer)
func (e *Engine) normalizeRequest(req OperationRequest) (entity, operation string) {
	entity = req.Entity
	operation = req.Operation

	// Auto-infer Entity from Scope/ResourceType if not provided
	if entity == "" && req.Scope == "system" {
		entity = "system"
	}
	if entity == "" && req.ResourceType != "" {
		// Infer from ResourceType (covers both scope=resource and when scope is not set)
		entity = req.ResourceType
	}

	// Special handling: dashboard_widget viewer operations
	// When ResourceType is dashboard_widget and Role is viewer, use viewer-specific operations
	if req.ResourceType == "dashboard_widget" && req.Role == "viewer" {
		entity = "dashboard_widget"
		// Map generic operations to viewer-specific ones
		switch req.Operation {
		case "assign_user_role", "assign_user_roles_batch":
			operation = "assign_viewer"
		case "delete_user_role":
			operation = "delete_viewer"
		}
	}

	return entity, operation
}

// GetOperationPolicy returns the policy for a specific entity operation
func (e *Engine) GetOperationPolicy(entity, operation string) (*OperationPolicy, error) {
	entityPolicy, ok := e.entityPolicies[entity]
	if !ok {
		return nil, fmt.Errorf("unknown entity: %s", entity)
	}

	opPolicy, ok := entityPolicy.Operations[operation]
	if !ok {
		return nil, fmt.Errorf("unknown operation %s for entity %s", operation, entity)
	}

	return opPolicy, nil
}

// CheckOperationPermission checks if the caller has permission to perform an operation
// If Entity is not provided, it will be inferred from Scope and ResourceType
// For widget viewer operations (ResourceType=dashboard_widget + Role=viewer), auto-adjusts to use viewer-specific policies
func (e *Engine) CheckOperationPermission(
	ctx context.Context,
	repo repository.RBACRepository,
	req OperationRequest,
) (bool, error) {
	// Normalize request: auto-infer Entity and adjust Operation for special cases
	entity, operation := e.normalizeRequest(req)

	policy, err := e.GetOperationPolicy(entity, operation)
	if err != nil {
		// For unknown entity/operation, return false (no permission) instead of error
		// This maintains backward compatibility with existing behavior
		return false, nil
	}

	// No permission required
	if policy.Permission == "" && policy.CheckScope == CheckScopeNone {
		return true, nil
	}

	switch policy.CheckScope {
	case CheckScopeNone:
		return true, nil

	case CheckScopeSystem:
		return e.checkSystemPermission(ctx, repo, req.CallerID, req.Namespace, policy.Permission)

	case CheckScopeResource:
		return e.checkResourcePermission(ctx, repo, req.CallerID, req.ResourceID, req.ResourceType, policy.Permission)

	case CheckScopeParentResource:
		if req.ParentResourceID == "" {
			return false, fmt.Errorf("parent_resource_id is required for this operation")
		}
		// Get parent entity type from policy
		parentType := e.getParentType(entity)
		return e.checkResourcePermission(ctx, repo, req.CallerID, req.ParentResourceID, parentType, policy.Permission)

	case CheckScopeSelfRoles:
		// For self_roles, this is typically checked differently (roles already loaded)
		// The service layer should handle this case
		return true, nil

	default:
		return false, fmt.Errorf("unknown check_scope: %s", policy.CheckScope)
	}
}

// getParentType returns the parent entity type for the given entity
func (e *Engine) getParentType(entity string) string {
	entityPolicy, ok := e.entityPolicies[entity]
	if ok && entityPolicy != nil && entityPolicy.ParentEntity != "" {
		return entityPolicy.ParentEntity
	}
	return "dashboard" // Default fallback
}

// mapPermission maps a permission based on the rule's permission mapping
func (e *Engine) mapPermission(rule *CheckPermissionRule, permission string) string {
	if rule.PermissionMapping == nil {
		return permission
	}
	if mapped, ok := rule.PermissionMapping[permission]; ok {
		return mapped
	}
	return permission
}

// inferEntity infers the entity name from scope and resourceType
func (e *Engine) inferEntity(scope, resourceType string) string {
	if scope == "system" {
		return "system"
	}
	if scope == "resource" && resourceType != "" {
		return resourceType
	}
	return "dashboard" // Default fallback
}

// CheckResourceAccess checks if user can access a resource (for CheckPermission API)
func (e *Engine) CheckResourceAccess(
	ctx context.Context,
	repo repository.RBACRepository,
	callerID, resourceID, resourceType, permission, parentResourceID string,
) (bool, error) {
	rule, ok := e.checkPermConfig.ResourceTypes[resourceType]
	if !ok {
		// No special rule, do standard check
		return e.checkResourcePermission(ctx, repo, callerID, resourceID, resourceType, permission)
	}

	switch rule.Inheritance {
	case "none":
		return e.checkResourcePermission(ctx, repo, callerID, resourceID, resourceType, permission)

	case "parent_if_no_roles":
		// First check if any roles exist on this resource
		count, err := repo.CountResourceRoles(ctx, resourceID, resourceType)
		if err != nil {
			return false, err
		}

		if count > 0 {
			// Whitelist mode: strict check on the resource itself
			return e.checkResourcePermission(ctx, repo, callerID, resourceID, resourceType, permission)
		}

		// Inheritance mode: check parent
		if parentResourceID == "" {
			return false, nil // Can't check parent without ID
		}

		// Map permission if needed
		mappedPerm := e.mapPermission(rule, permission)

		return e.checkResourcePermission(ctx, repo, callerID, parentResourceID, rule.ParentType, mappedPerm)

	default:
		return e.checkResourcePermission(ctx, repo, callerID, resourceID, resourceType, permission)
	}
}

// checkSystemPermission checks if user has system-level permission
func (e *Engine) checkSystemPermission(
	ctx context.Context,
	repo repository.RBACRepository,
	userID, namespace, permission string,
) (bool, error) {
	requiredRoles := e.GetRolesWithPermission(permission, true)
	if len(requiredRoles) == 0 {
		return false, nil
	}
	return repo.HasAnySystemRole(ctx, userID, namespace, requiredRoles)
}

// checkResourcePermission checks if user has resource-level permission
func (e *Engine) checkResourcePermission(
	ctx context.Context,
	repo repository.RBACRepository,
	userID, resourceID, resourceType, permission string,
) (bool, error) {
	requiredRoles := e.GetRolesWithPermission(permission, false)
	if len(requiredRoles) == 0 {
		return false, nil
	}
	return repo.HasAnyResourceRole(ctx, userID, resourceID, resourceType, requiredRoles)
}

// GetRolesWithPermission returns roles that have the given permission
func (e *Engine) GetRolesWithPermission(permission string, isSystem bool) []string {
	var rolePerms map[string][]string
	if isSystem {
		rolePerms = e.systemRolePerms
	} else {
		rolePerms = e.resourceRolePerms
	}

	var roles []string
	for role, perms := range rolePerms {
		for _, p := range perms {
			if p == permission {
				roles = append(roles, role)
				break
			}
		}
	}
	sort.Strings(roles)
	return roles
}

// CheckRolesHavePermission checks if any of the provided roles have the permission
func (e *Engine) CheckRolesHavePermission(roles []*model.UserRole, permission string) bool {
	systemAllowed := e.GetRolesWithPermission(permission, true)
	resourceAllowed := e.GetRolesWithPermission(permission, false)

	allowedMap := make(map[string]bool)
	for _, r := range systemAllowed {
		allowedMap["system:"+r] = true
	}
	for _, r := range resourceAllowed {
		allowedMap["resource:"+r] = true
	}

	for _, role := range roles {
		key := role.Scope + ":" + role.Role
		if allowedMap[key] {
			return true
		}
	}
	return false
}

// CheckSelfRolesPermission checks if the caller's roles have permission for get_my_roles operation
// Auto-infers entity from scope/resourceType and looks up permission from policy
func (e *Engine) CheckSelfRolesPermission(roles []*model.UserRole, scope, resourceType string) bool {
	// Infer entity from scope/resourceType
	entity := e.inferEntity(scope, resourceType)

	// Get the get_my_roles policy
	opPolicy, err := e.GetOperationPolicy(entity, "get_my_roles")
	if err != nil {
		// For unknown entity, use default permission
		perm := "resource." + resourceType + ".read"
		if scope == "system" {
			perm = model.PermPlatformSystemRead
		}
		return e.CheckRolesHavePermission(roles, perm)
	}

	return e.CheckRolesHavePermission(roles, opPolicy.Permission)
}
