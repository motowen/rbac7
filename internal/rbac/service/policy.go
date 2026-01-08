package service

import (
	"context"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
	"sort"
)

// SystemRolePermissions maps System Role Names to their Prmissions
// Based on User provided JSON
var SystemRolePermissions = map[string][]string{
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
		model.PermResourceLibraryWidgetGetMember, // Can view library widget whitelist
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
		model.PermResourceLibraryWidgetGetMember, // Can view library widget whitelist
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

// ResourceRolePermissions maps Resource Role Names to their Permissions (Dashboard)
var ResourceRolePermissions = map[string][]string{
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
		model.PermResourceDashboardWidgetGetMember, // Can view dashboard_widget whitelist
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
		model.PermResourceDashboardWidgetGetMember, // Can view dashboard_widget whitelist
	},
	"editor": {
		model.PermResourceDashboardRead,
		model.PermResourceDashboardUpdate,
		model.PermResourceDashboardAddWidget,
		model.PermResourceDashboardRemoveWidget,
		model.PermResourceDashboardAddWidgetViewer,
		model.PermResourceDashboardWidgetRead,
		model.PermResourceDashboardWidgetGetMember, // Can view dashboard_widget whitelist
	},
	"viewer": {
		model.PermResourceDashboardRead,
		model.PermResourceDashboardWidgetRead,
	},
}

// Library Widget Role Permissions (only viewer role)
var LibraryWidgetRolePermissions = map[string][]string{
	"viewer": {model.PermResourceLibraryWidgetRead},
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

// GetResourceRolesWithPermission returns a list of role names (in resource scope) that possess the given permission.
func GetResourceRolesWithPermission(permission string) []string {
	var roles []string
	// Check dashboard/widget permissions
	for role, perms := range ResourceRolePermissions {
		for _, p := range perms {
			if p == permission {
				roles = append(roles, role)
				break
			}
		}
	}

	// Also check library_widget permissions
	for role, perms := range LibraryWidgetRolePermissions {
		for _, p := range perms {
			if p == permission {
				// Avoid duplicates
				found := false
				for _, r := range roles {
					if r == role {
						found = true
						break
					}
				}
				if !found {
					roles = append(roles, role)
				}
				break
			}
		}
	}

	sort.Strings(roles)
	return roles
}

// CheckResourcePermission checks if the user has any role in the resource that grants the required permission.
func CheckResourcePermission(ctx context.Context, repo repository.RBACRepository, userID, resourceID, resourceType, permission string) (bool, error) {
	requiredRoles := GetResourceRolesWithPermission(permission)
	if len(requiredRoles) == 0 {
		return false, nil
	}
	return repo.HasAnyResourceRole(ctx, userID, resourceID, resourceType, requiredRoles)
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
	// 1. Get all roles that have this permission (System)
	allowedSystemRoles := GetRolesWithPermission(permission)
	// 2. Get all roles that have this permission (Resource)
	allowedResourceRoles := GetResourceRolesWithPermission(permission)

	allowedMap := make(map[string]bool)
	for _, r := range allowedSystemRoles {
		allowedMap["system:"+r] = true
	}
	for _, r := range allowedResourceRoles {
		allowedMap["resource:"+r] = true
	}

	for _, role := range roles {
		if role.Scope == model.ScopeSystem {
			if allowedMap["system:"+role.Role] {
				return true
			}
		} else if role.Scope == model.ScopeResource {
			if allowedMap["resource:"+role.Role] {
				return true
			}
		}
	}
	return false
}
