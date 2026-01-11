package policy

import (
	"testing"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
)

// Helper function to convert []string permissions to map[string]bool for easy lookup
func permissionsToMap(perms []string) map[string]bool {
	m := make(map[string]bool)
	for _, p := range perms {
		m[p] = true
	}
	return m
}

// extractRoles extracts all role names from role permissions map
func extractRoles(rolePerms map[string][]string) []string {
	roles := make([]string, 0, len(rolePerms))
	for role := range rolePerms {
		roles = append(roles, role)
	}
	return roles
}

// extractUniquePermissions extracts all unique permissions from role permissions map
func extractUniquePermissions(rolePerms map[string][]string) []string {
	permSet := make(map[string]bool)
	for _, perms := range rolePerms {
		for _, p := range perms {
			permSet[p] = true
		}
	}
	permissions := make([]string, 0, len(permSet))
	for p := range permSet {
		permissions = append(permissions, p)
	}
	return permissions
}

// TestSystemRolePermissions tests all system permissions against all system roles
// All data is loaded from JSON files - no hardcoded values
func TestSystemRolePermissions(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	loader := NewLoader()
	systemRolePerms, err := loader.LoadSystemRolePermissions()
	assert.NoError(t, err)

	// Extract roles and permissions from JSON
	systemRoles := extractRoles(systemRolePerms)
	systemPermissions := extractUniquePermissions(systemRolePerms)

	t.Logf("Testing %d system roles with %d unique permissions", len(systemRoles), len(systemPermissions))

	for _, role := range systemRoles {
		rolePerms := permissionsToMap(systemRolePerms[role])
		for _, perm := range systemPermissions {
			t.Run(role+"/"+perm, func(t *testing.T) {
				roles := []*model.UserRole{
					{UserID: "user1", Role: role, Scope: model.ScopeSystem, Namespace: "ns1"},
				}
				expected := rolePerms[perm]
				result := engine.CheckRolesHavePermission(roles, perm)
				assert.Equal(t, expected, result,
					"Role %s should have permission %s = %v", role, perm, expected)
			})
		}
	}
}

// TestResourceRolePermissions tests all resource permissions against all resource roles
// All data is loaded from JSON files - no hardcoded values
func TestResourceRolePermissions(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	loader := NewLoader()
	resourceRolePerms, err := loader.LoadResourceRolePermissions()
	assert.NoError(t, err)

	// Extract roles and permissions from JSON
	resourceRoles := extractRoles(resourceRolePerms)
	resourcePermissions := extractUniquePermissions(resourceRolePerms)

	t.Logf("Testing %d resource roles with %d unique permissions", len(resourceRoles), len(resourcePermissions))

	for _, role := range resourceRoles {
		rolePerms := permissionsToMap(resourceRolePerms[role])
		for _, perm := range resourcePermissions {
			t.Run(role+"/"+perm, func(t *testing.T) {
				roles := []*model.UserRole{
					{UserID: "user1", Role: role, Scope: model.ScopeResource, ResourceID: "res1", ResourceType: "dashboard"},
				}
				expected := rolePerms[perm]
				result := engine.CheckRolesHavePermission(roles, perm)
				assert.Equal(t, expected, result,
					"Role %s should have permission %s = %v", role, perm, expected)
			})
		}
	}
}

// TestLibraryWidgetPermissions tests library widget specific permissions
// Library widget viewer permissions are accessed via resource scope role
func TestLibraryWidgetPermissions(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	loader := NewLoader()
	resourceRolePerms, err := loader.LoadResourceRolePermissions()
	assert.NoError(t, err)
	systemRolePerms, err := loader.LoadSystemRolePermissions()
	assert.NoError(t, err)

	// Library widget permissions to test
	libraryWidgetPermissions := []string{
		model.PermResourceLibraryWidgetRead,
		model.PermResourceLibraryWidgetGetMember,
	}

	t.Run("resource_viewer_library_widget_permissions", func(t *testing.T) {
		viewerPerms := permissionsToMap(resourceRolePerms["viewer"])
		for _, perm := range libraryWidgetPermissions {
			t.Run(perm, func(t *testing.T) {
				roles := []*model.UserRole{
					{UserID: "user1", Role: "viewer", Scope: model.ScopeResource, ResourceID: "lw1", ResourceType: "library_widget"},
				}
				expected := viewerPerms[perm]
				result := engine.CheckRolesHavePermission(roles, perm)
				assert.Equal(t, expected, result,
					"Resource viewer should have permission %s = %v", perm, expected)
			})
		}
	})

	// System owner/admin can get library widget members (defined in system_roles.json)
	t.Run("system_owner_library_widget_permissions", func(t *testing.T) {
		ownerPerms := permissionsToMap(systemRolePerms["owner"])
		for _, perm := range libraryWidgetPermissions {
			t.Run(perm, func(t *testing.T) {
				roles := []*model.UserRole{
					{UserID: "user1", Role: "owner", Scope: model.ScopeSystem, Namespace: "ns1"},
				}
				expected := ownerPerms[perm]
				result := engine.CheckRolesHavePermission(roles, perm)
				assert.Equal(t, expected, result,
					"System owner should have permission %s = %v", perm, expected)
			})
		}
	})

	t.Run("system_admin_library_widget_permissions", func(t *testing.T) {
		adminPerms := permissionsToMap(systemRolePerms["admin"])
		for _, perm := range libraryWidgetPermissions {
			t.Run(perm, func(t *testing.T) {
				roles := []*model.UserRole{
					{UserID: "user1", Role: "admin", Scope: model.ScopeSystem, Namespace: "ns1"},
				}
				expected := adminPerms[perm]
				result := engine.CheckRolesHavePermission(roles, perm)
				assert.Equal(t, expected, result,
					"System admin should have permission %s = %v", perm, expected)
			})
		}
	})
}

// TestDashboardWidgetPermissions tests dashboard widget specific permissions
// Dashboard widget viewer permissions are accessed via parent dashboard role
func TestDashboardWidgetPermissions(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	loader := NewLoader()
	resourceRolePerms, err := loader.LoadResourceRolePermissions()
	assert.NoError(t, err)

	// Dashboard widget permissions to test
	dashboardWidgetPermissions := []string{
		model.PermResourceDashboardWidgetRead,
		model.PermResourceDashboardWidgetGetMember,
	}

	// Extract all resource roles
	resourceRoles := extractRoles(resourceRolePerms)

	// Test all dashboard roles for widget permissions (widget access is via parent dashboard)
	for _, role := range resourceRoles {
		rolePerms := permissionsToMap(resourceRolePerms[role])
		for _, perm := range dashboardWidgetPermissions {
			t.Run("dashboard_"+role+"/"+perm, func(t *testing.T) {
				roles := []*model.UserRole{
					{UserID: "user1", Role: role, Scope: model.ScopeResource, ResourceID: "dash1", ResourceType: "dashboard"},
				}
				expected := rolePerms[perm]
				result := engine.CheckRolesHavePermission(roles, perm)
				assert.Equal(t, expected, result,
					"Dashboard role %s should have widget permission %s = %v", role, perm, expected)
			})
		}
	}
}

// TestNoPermissionCases tests fundamental permission denial cases
func TestNoPermissionCases(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	loader := NewLoader()
	systemRolePerms, _ := loader.LoadSystemRolePermissions()
	permissions := extractUniquePermissions(systemRolePerms)

	// Test: Empty roles have no permissions
	t.Run("empty_roles_no_permission", func(t *testing.T) {
		roles := []*model.UserRole{}
		for _, perm := range permissions {
			result := engine.CheckRolesHavePermission(roles, perm)
			assert.False(t, result, "Empty roles should not have permission %s", perm)
		}
	})

	// Test: Non-existent role has no permissions
	t.Run("unknown_role_no_permission", func(t *testing.T) {
		roles := []*model.UserRole{
			{UserID: "user1", Role: "nonexistent_role", Scope: model.ScopeSystem, Namespace: "ns1"},
		}
		for _, perm := range permissions {
			result := engine.CheckRolesHavePermission(roles, perm)
			assert.False(t, result, "Unknown role should not have permission %s", perm)
		}
	})
}

// TestRolePermissionCounts validates the JSON data is loaded correctly
func TestRolePermissionCounts(t *testing.T) {
	loader := NewLoader()

	t.Run("system_roles_loaded", func(t *testing.T) {
		perms, err := loader.LoadSystemRolePermissions()
		assert.NoError(t, err)
		assert.NotEmpty(t, perms, "System roles should not be empty")

		roles := extractRoles(perms)
		permissions := extractUniquePermissions(perms)

		t.Logf("Loaded %d system roles with %d unique permissions", len(roles), len(permissions))

		for _, role := range roles {
			assert.NotEmpty(t, perms[role], "Role %s should have at least one permission", role)
		}
	})

	t.Run("resource_roles_loaded", func(t *testing.T) {
		perms, err := loader.LoadResourceRolePermissions()
		assert.NoError(t, err)
		assert.NotEmpty(t, perms, "Resource roles should not be empty")

		roles := extractRoles(perms)
		permissions := extractUniquePermissions(perms)

		t.Logf("Loaded %d resource roles with %d unique permissions", len(roles), len(permissions))

		for _, role := range roles {
			assert.NotEmpty(t, perms[role], "Role %s should have at least one permission", role)
		}
	})
}
