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

	// Initialize with default role permissions (can be externalized later)
	engine := &Engine{
		entityPolicies:    entityPolicies,
		checkPermConfig:   checkPermConfig,
		systemRolePerms:   getSystemRolePermissions(),
		resourceRolePerms: getResourceRolePermissions(),
	}

	return engine, nil
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
func (e *Engine) CheckOperationPermission(
	ctx context.Context,
	repo repository.RBACRepository,
	req OperationRequest,
) (bool, error) {
	// Auto-infer Entity from Scope/ResourceType if not provided
	entity := req.Entity
	if entity == "" {
		if req.Scope == "system" {
			entity = "system"
		} else if req.Scope == "resource" && req.ResourceType != "" {
			entity = req.ResourceType
		}
	}

	policy, err := e.GetOperationPolicy(entity, req.Operation)
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
		entityPolicy := e.entityPolicies[req.Entity]
		parentType := entityPolicy.ParentEntity
		if parentType == "" {
			parentType = "dashboard" // Default fallback
		}
		return e.checkResourcePermission(ctx, repo, req.CallerID, req.ParentResourceID, parentType, policy.Permission)

	case CheckScopeSelfRoles:
		// For self_roles, this is typically checked differently (roles already loaded)
		// The service layer should handle this case
		return true, nil

	default:
		return false, fmt.Errorf("unknown check_scope: %s", policy.CheckScope)
	}
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
		mappedPerm := permission
		if rule.PermissionMapping != nil {
			if mapped, ok := rule.PermissionMapping[permission]; ok {
				mappedPerm = mapped
			}
		}

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
	requiredRoles := e.getRolesWithPermission(permission, true)
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
	requiredRoles := e.getRolesWithPermission(permission, false)
	if len(requiredRoles) == 0 {
		return false, nil
	}
	return repo.HasAnyResourceRole(ctx, userID, resourceID, resourceType, requiredRoles)
}

// getRolesWithPermission returns roles that have the given permission
func (e *Engine) getRolesWithPermission(permission string, isSystem bool) []string {
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
	systemAllowed := e.getRolesWithPermission(permission, true)
	resourceAllowed := e.getRolesWithPermission(permission, false)

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
	var entity string
	if scope == "system" {
		entity = "system"
	} else if scope == "resource" && resourceType != "" {
		entity = resourceType
	} else {
		entity = "dashboard" // Default fallback
	}

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

func getSystemRolePermissions() map[string][]string {
	return map[string][]string{
		"moderator": {
			model.PermPlatformSystemCreate,
			model.PermPlatformSystemRead,
			model.PermPlatformSystemAddOwner,
		},
		"owner": {
			model.PermPlatformSystemUpdate,
			model.PermPlatformSystemRead,
			model.PermPlatformSystemAddMember,
			model.PermPlatformSystemRemoveMember,
			model.PermPlatformSystemGetMember,
			model.PermPlatformSystemTransferOwner,
			model.PermSystemResourceCreate,
			model.PermSystemResourceRead,
			model.PermSystemResourceDelete,
			model.PermSystemResourceUpdate,
			model.PermSystemResourcePublish,
			model.PermResourceLibraryWidgetGetMember,
		},
		"admin": {
			model.PermPlatformSystemUpdate,
			model.PermPlatformSystemRead,
			model.PermPlatformSystemAddMember,
			model.PermPlatformSystemRemoveMember,
			model.PermPlatformSystemGetMember,
			model.PermSystemResourceCreate,
			model.PermSystemResourceRead,
			model.PermSystemResourceDelete,
			model.PermSystemResourceUpdate,
			model.PermSystemResourcePublish,
			model.PermResourceLibraryWidgetGetMember,
		},
		"dev_user": {
			model.PermPlatformSystemRead,
			model.PermSystemResourceCreate,
			model.PermSystemResourceRead,
			model.PermSystemResourceDelete,
			model.PermSystemResourceUpdate,
			model.PermSystemResourcePublish,
		},
		"viewer": {
			model.PermPlatformSystemRead,
			model.PermSystemResourceRead,
		},
	}
}

// getResourceRolePermissions returns resource role permission mappings
func getResourceRolePermissions() map[string][]string {
	return map[string][]string{
		"owner": {
			model.PermResourceDashboardRead,
			model.PermResourceDashboardUpdate,
			model.PermResourceDashboardDelete,
			model.PermResourceDashboardAddMember,
			model.PermResourceDashboardRemoveMember,
			model.PermResourceDashboardGetMember,
			model.PermResourceDashboardTransferOwner,
			model.PermResourceDashboardAddWidget,
			model.PermResourceDashboardRemoveWidget,
			model.PermResourceDashboardAddWidgetViewer,
			model.PermResourceDashboardWidgetRead,
			model.PermResourceDashboardWidgetGetMember,
			model.PermResourceLibraryWidgetRead,
		},
		"admin": {
			model.PermResourceDashboardRead,
			model.PermResourceDashboardUpdate,
			model.PermResourceDashboardDelete,
			model.PermResourceDashboardAddMember,
			model.PermResourceDashboardRemoveMember,
			model.PermResourceDashboardGetMember,
			model.PermResourceDashboardAddWidget,
			model.PermResourceDashboardRemoveWidget,
			model.PermResourceDashboardAddWidgetViewer,
			model.PermResourceDashboardWidgetRead,
			model.PermResourceDashboardWidgetGetMember,
			model.PermResourceLibraryWidgetRead,
		},
		"editor": {
			model.PermResourceDashboardRead,
			model.PermResourceDashboardUpdate,
			model.PermResourceDashboardAddWidget,
			model.PermResourceDashboardRemoveWidget,
			model.PermResourceDashboardAddWidgetViewer,
			model.PermResourceDashboardWidgetRead,
			model.PermResourceDashboardWidgetGetMember,
		},
		"viewer": {
			model.PermResourceDashboardRead,
			model.PermResourceDashboardWidgetRead,
			model.PermResourceLibraryWidgetRead,
		},
	}
}
