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

	// Resource Scope Permissions (Dashboard)
	PermResourceDashboardRead          = "resource.dashboard.read"
	PermResourceDashboardUpdate        = "resource.dashboard.update"
	PermResourceDashboardDelete        = "resource.dashboard.delete"
	PermResourceDashboardAddMember     = "resource.dashboard.add_member"
	PermResourceDashboardRemoveMember  = "resource.dashboard.remove_member"
	PermResourceDashboardGetMember     = "resource.dashboard.get_member"
	PermResourceDashboardTransferOwner = "resource.dashboard.transfer_owner"

	// Dashboard Widget Permissions
	PermResourceDashboardAddWidget       = "resource.dashboard.add_widget"
	PermResourceDashboardRemoveWidget    = "resource.dashboard.remove_widget"
	PermResourceDashboardAddWidgetViewer = "resource.dashboard.add_widget_viewer"
	PermResourceDashboardWidgetRead      = "resource.dashboard_widget.read"
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

// ResourceRolePermissions maps Resource Role Names to their Permissions (Dashboard)
var ResourceRolePermissions = map[string][]string{
	"owner": {
		PermResourceDashboardRead,
		PermResourceDashboardUpdate,
		PermResourceDashboardDelete,
		PermResourceDashboardAddMember,
		PermResourceDashboardRemoveMember,
		PermResourceDashboardGetMember,
		PermResourceDashboardTransferOwner,
		PermResourceDashboardAddWidget,
		PermResourceDashboardRemoveWidget,
		PermResourceDashboardAddWidgetViewer,
		PermResourceDashboardWidgetRead,
	},
	"admin": {
		PermResourceDashboardRead,
		PermResourceDashboardUpdate,
		PermResourceDashboardDelete,
		PermResourceDashboardAddMember,
		PermResourceDashboardRemoveMember,
		PermResourceDashboardGetMember,
		PermResourceDashboardAddWidget,
		PermResourceDashboardRemoveWidget,
		PermResourceDashboardAddWidgetViewer,
		PermResourceDashboardWidgetRead,
	},
	"editor": {
		PermResourceDashboardRead,
		PermResourceDashboardUpdate,
		PermResourceDashboardAddWidget,
		PermResourceDashboardRemoveWidget,
		PermResourceDashboardAddWidgetViewer,
		PermResourceDashboardWidgetRead,
	},
	"viewer": {
		PermResourceDashboardRead,
		PermResourceDashboardWidgetRead,
	},
}

// Library Widget Role Permissions (only viewer role)
var LibraryWidgetRolePermissions = map[string][]string{
	"viewer": {PermResourceLibraryWidgetRead},
}

// PermResourceLibraryWidgetRead permission constant
const PermResourceLibraryWidgetRead = "resource.library_widget.read"

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
