package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEngine(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)
	assert.NotNil(t, engine)
	assert.NotEmpty(t, engine.entityPolicies)
	assert.NotNil(t, engine.checkPermConfig)
}

func TestGetOperationPolicy(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	t.Run("unknown entity returns error", func(t *testing.T) {
		_, err := engine.GetOperationPolicy("unknown", "assign_owner")
		assert.Error(t, err)
	})

	t.Run("unknown operation returns error", func(t *testing.T) {
		_, err := engine.GetOperationPolicy("system", "unknown_op")
		assert.Error(t, err)
	})
}

// TestAllOperationsPolicies verifies all JSON policy files are correctly loaded
func TestAllOperationsPolicies(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	// Define expected policies for all operations in JSON files
	tests := []struct {
		entity                 string
		operation              string
		expectedPermission     string
		expectedCheckScope     CheckScope
		expectedNamespaceReq   bool
		expectedParentRequired bool
	}{
		// === system.json ===
		{"system", "assign_owner", "platform.system.add_owner", CheckScopeSystem, false, false},
		{"system", "transfer_owner", "platform.system.transfer_owner", CheckScopeSystem, false, false},
		{"system", "assign_user_role", "platform.system.add_member", CheckScopeSystem, false, false},
		{"system", "assign_user_roles_batch", "platform.system.add_member", CheckScopeSystem, false, false},
		{"system", "delete_user_role", "platform.system.remove_member", CheckScopeSystem, false, false},
		{"system", "get_members", "platform.system.get_member", CheckScopeSystem, false, false},
		{"system", "get_my_roles", "platform.system.read", CheckScopeSelfRoles, false, false},

		// === dashboard.json ===
		{"dashboard", "assign_owner", "", CheckScopeNone, false, false},
		{"dashboard", "transfer_owner", "resource.dashboard.transfer_owner", CheckScopeResource, false, false},
		{"dashboard", "assign_user_role", "resource.dashboard.add_member", CheckScopeResource, false, false},
		{"dashboard", "assign_user_roles_batch", "resource.dashboard.add_member", CheckScopeResource, false, false},
		{"dashboard", "delete_user_role", "resource.dashboard.remove_member", CheckScopeResource, false, false},
		{"dashboard", "get_members", "resource.dashboard.get_member", CheckScopeResource, false, false},
		{"dashboard", "get_my_roles", "resource.dashboard.read", CheckScopeSelfRoles, false, false},

		// === dashboard_widget.json ===
		{"dashboard_widget", "assign_viewer", "resource.dashboard.add_widget_viewer", CheckScopeParentResource, false, true},
		{"dashboard_widget", "assign_user_roles_batch", "resource.dashboard.add_widget_viewer", CheckScopeParentResource, false, true},
		{"dashboard_widget", "delete_viewer", "resource.dashboard.add_widget_viewer", CheckScopeParentResource, false, true},
		{"dashboard_widget", "get_members", "resource.dashboard_widget.get_member", CheckScopeParentResource, false, true},
		{"dashboard_widget", "get_my_roles", "resource.dashboard_widget.read", CheckScopeSelfRoles, false, false},

		// === library_widget.json ===
		{"library_widget", "assign_viewer", "platform.system.add_member", CheckScopeSystem, true, false},
		{"library_widget", "assign_viewers_batch", "platform.system.add_member", CheckScopeSystem, true, false},
		{"library_widget", "delete_viewer", "platform.system.remove_member", CheckScopeSystem, true, false},
		{"library_widget", "get_members", "resource.library_widget.get_member", CheckScopeSystem, true, false},
		{"library_widget", "get_my_roles", "resource.library_widget.read", CheckScopeSelfRoles, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.entity+"/"+tc.operation, func(t *testing.T) {
			policy, err := engine.GetOperationPolicy(tc.entity, tc.operation)
			assert.NoError(t, err, "operation %s/%s should exist", tc.entity, tc.operation)
			assert.NotNil(t, policy, "policy should not be nil")

			assert.Equal(t, tc.expectedPermission, policy.Permission,
				"permission mismatch for %s/%s", tc.entity, tc.operation)
			assert.Equal(t, tc.expectedCheckScope, policy.CheckScope,
				"check_scope mismatch for %s/%s", tc.entity, tc.operation)
			assert.Equal(t, tc.expectedNamespaceReq, policy.NamespaceRequired,
				"namespace_required mismatch for %s/%s", tc.entity, tc.operation)
			assert.Equal(t, tc.expectedParentRequired, policy.ParentResourceRequired,
				"parent_resource_required mismatch for %s/%s", tc.entity, tc.operation)
		})
	}
}

func TestEntityPoliciesLoaded(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	// Verify all 4 entities are loaded
	expectedEntities := []string{"system", "dashboard", "dashboard_widget", "library_widget"}
	for _, entity := range expectedEntities {
		_, ok := engine.entityPolicies[entity]
		assert.True(t, ok, "entity %s should be loaded", entity)
	}
}

func TestCheckPermissionConfigLoaded(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	// Verify check permission config
	assert.NotNil(t, engine.checkPermConfig.ResourceTypes["dashboard"])
	assert.NotNil(t, engine.checkPermConfig.ResourceTypes["dashboard_widget"])
	assert.NotNil(t, engine.checkPermConfig.ResourceTypes["library_widget"])

	// dashboard_widget has parent inheritance
	dwRule := engine.checkPermConfig.ResourceTypes["dashboard_widget"]
	assert.Equal(t, "parent_if_no_roles", dwRule.Inheritance)
	assert.Equal(t, "dashboard", dwRule.ParentType)
}

func TestGetRolesWithPermission(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	t.Run("system add_member permission returns owner and admin", func(t *testing.T) {
		roles := engine.GetRolesWithPermission("platform.system.add_member", true)
		assert.Contains(t, roles, "owner")
		assert.Contains(t, roles, "admin")
		assert.NotContains(t, roles, "viewer")
	})

	t.Run("resource read permission returns multiple roles", func(t *testing.T) {
		roles := engine.GetRolesWithPermission("resource.dashboard.read", false)
		assert.Contains(t, roles, "owner")
		assert.Contains(t, roles, "admin")
		assert.Contains(t, roles, "editor")
		assert.Contains(t, roles, "viewer")
	})
}
