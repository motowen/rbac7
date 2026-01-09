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

	t.Run("system assign_owner", func(t *testing.T) {
		policy, err := engine.GetOperationPolicy("system", "assign_owner")
		assert.NoError(t, err)
		assert.Equal(t, "platform.system.add_owner", policy.Permission)
		assert.Equal(t, CheckScopeSystem, policy.CheckScope)
	})

	t.Run("library_widget assign_viewer", func(t *testing.T) {
		policy, err := engine.GetOperationPolicy("library_widget", "assign_viewer")
		assert.NoError(t, err)
		assert.Equal(t, "platform.system.add_member", policy.Permission)
		assert.Equal(t, CheckScopeSystem, policy.CheckScope)
		assert.True(t, policy.NamespaceRequired)
	})

	t.Run("dashboard_widget assign_viewer", func(t *testing.T) {
		policy, err := engine.GetOperationPolicy("dashboard_widget", "assign_viewer")
		assert.NoError(t, err)
		assert.Equal(t, "resource.dashboard.add_widget_viewer", policy.Permission)
		assert.Equal(t, CheckScopeParentResource, policy.CheckScope)
		assert.True(t, policy.ParentResourceRequired)
	})

	t.Run("dashboard assign_owner requires no permission", func(t *testing.T) {
		policy, err := engine.GetOperationPolicy("dashboard", "assign_owner")
		assert.NoError(t, err)
		assert.Equal(t, "", policy.Permission)
		assert.Equal(t, CheckScopeNone, policy.CheckScope)
	})

	t.Run("unknown entity returns error", func(t *testing.T) {
		_, err := engine.GetOperationPolicy("unknown", "assign_owner")
		assert.Error(t, err)
	})

	t.Run("unknown operation returns error", func(t *testing.T) {
		_, err := engine.GetOperationPolicy("system", "unknown_op")
		assert.Error(t, err)
	})
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
