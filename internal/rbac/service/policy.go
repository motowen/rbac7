package service

import (
	"context"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
	"sort"
)

// Permission constants for strict typing
const (
	PermPlatformSystemCreate        = "platform.system.create"
	PermPlatformSystemRead          = "platform.system.read"
	PermPlatformSystemAddOwner      = "platform.system.add_owner"
	PermPlatformSystemUpdate        = "platform.system.update"
	PermPlatformSystemAddMember     = "platform.system.add_member" // Used for AssignSystemUserRole
	PermPlatformSystemRemoveMember  = "platform.system.remove_member"
	PermPlatformSystemGetMember     = "platform.system.get_member" // Used for GetUserRoles (List)
	PermPlatformSystemTransferOwner = "platform.system.transfer_owner"
	PermSystemResourceCreate        = "system.resource.create"
	PermSystemResourceRead          = "system.resource.read"
	PermSystemResourceDelete        = "system.resource.delete"
	PermSystemResourceUpdate        = "system.resource.update"
	PermSystemResourcePublish       = "system.resource.publish"
)

// SystemRolePermissions maps System Role Names to their Prmissions
// Based on User provided JSON
var SystemRolePermissions = map[string][]string{
	"moderator": {
		PermPlatformSystemCreate,
		PermPlatformSystemRead,
		PermPlatformSystemAddOwner,
	},
	"owner": {
		PermPlatformSystemUpdate,
		PermPlatformSystemRead,
		PermPlatformSystemAddMember,
		PermPlatformSystemRemoveMember,
		PermPlatformSystemGetMember,
		PermPlatformSystemTransferOwner,
		PermSystemResourceCreate,
		PermSystemResourceRead,
		PermSystemResourceDelete,
		PermSystemResourceUpdate,
		PermSystemResourcePublish,
	},
	"admin": {
		PermPlatformSystemUpdate,
		PermPlatformSystemRead,
		PermPlatformSystemAddMember,
		PermPlatformSystemRemoveMember,
		PermPlatformSystemGetMember,
		PermSystemResourceCreate,
		PermSystemResourceRead,
		PermSystemResourceDelete,
		PermSystemResourceUpdate,
		PermSystemResourcePublish,
	},
	"dev_user": {
		PermPlatformSystemRead,
		PermSystemResourceCreate,
		PermSystemResourceRead,
		PermSystemResourceDelete,
		PermSystemResourceUpdate,
		PermSystemResourcePublish,
	},
	"viewer": {
		PermPlatformSystemRead,
		PermSystemResourceRead,
	},
}

// GetRolesWithPermission returns a list of role names (in system scope) that possess the given permission.
func GetRolesWithPermission(permission string) []string {
	var roles []string
	for role, perms := range SystemRolePermissions {
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

// CheckSystemPermission checks if the user has any role in the system namespace that grants the required permission.
func CheckSystemPermission(ctx context.Context, repo repository.RBACRepository, userID, namespace, permission string) (bool, error) {
	requiredRoles := GetRolesWithPermission(permission)
	if len(requiredRoles) == 0 {
		return false, nil // Permission not granted to any role
	}
	return repo.HasAnySystemRole(ctx, userID, namespace, requiredRoles)
}

// CheckRolesHavePermission checks if any of the provided user roles grant the required permission.
// This is useful when roles are already loaded (e.g. GetUserRolesMe).
func CheckRolesHavePermission(roles []*model.UserRole, permission string) bool {
	// 1. Get all roles that have this permission
	allowedRoles := GetRolesWithPermission(permission)
	if len(allowedRoles) == 0 {
		return false
	}

	// 2. Create a map for O(1) lookup
	allowedMap := make(map[string]bool)
	for _, r := range allowedRoles {
		allowedMap[r] = true
	}

	// 3. Check if any of the user's roles matching the system scope are in the allow list
	for _, role := range roles {
		// Assumption: This check is primarily for System Scope permissions.
		// If we extend to Resource scope, we might need to check role.Scope.
		if role.Scope == model.ScopeSystem {
			if allowedMap[role.Role] {
				return true
			}
		}
	}
	return false
}
