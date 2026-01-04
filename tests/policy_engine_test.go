package tests

import (
	"rbac7/internal/rbac/policy"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyEngine_Unit(t *testing.T) {
	jsonPolicy := `
	{
		"test_action": [
			{
				"conditions": { "role": "admin", "type": "special" },
				"permission": "perm.special.{type}",
				"scope": "global"
			},
			{
				"conditions": { "role": "viewer" },
				"permission": "perm.viewer",
				"scope": "resource"
			},
			{
				"permission": "perm.default"
			}
		]
	}`

	engine := policy.NewPolicyEngine()
	err := engine.LoadPoliciesFromString(jsonPolicy)
	assert.NoError(t, err)

	t.Run("Match Specific Condition", func(t *testing.T) {
		ctx := map[string]interface{}{
			"role": "admin",
			"type": "special",
		}
		perm, scope, err := engine.GetPermission("test_action", ctx)
		assert.NoError(t, err)
		assert.Equal(t, "perm.special.special", perm) // Interpolated
		assert.Equal(t, "global", scope)
	})

	t.Run("Match Second Condition", func(t *testing.T) {
		ctx := map[string]interface{}{
			"role": "viewer",
			"type": "other",
		}
		perm, scope, err := engine.GetPermission("test_action", ctx)
		assert.NoError(t, err)
		assert.Equal(t, "perm.viewer", perm)
		assert.Equal(t, "resource", scope)
	})

	t.Run("Match Default (No Conditions)", func(t *testing.T) {
		ctx := map[string]interface{}{
			"role": "stranger",
		}
		perm, scope, err := engine.GetPermission("test_action", ctx)
		assert.NoError(t, err)
		assert.Equal(t, "perm.default", perm)
		assert.Equal(t, "resource", scope) // Default scope
	})

	t.Run("Unknown Action", func(t *testing.T) {
		_, _, err := engine.GetPermission("unknown", nil)
		assert.Error(t, err)
	})

	t.Run("Missing Context Key for Condition", func(t *testing.T) {
		// Should skip the first rule because 'type' is missing, match second if role matches, or fall through
		ctx := map[string]interface{}{
			"role": "admin",
			// type missing
		}
		// First rule requires type=special. Match fails (key missing).
		// Second rule requires role=viewer. Match fails (admin != viewer).
		// Third rule has no conditions. Expect default.
		perm, _, err := engine.GetPermission("test_action", ctx)
		assert.NoError(t, err)
		assert.Equal(t, "perm.default", perm)
	})
}

func TestPolicyEngine_DefaultPolicies(t *testing.T) {
	// This tests the interaction with the embedded policies.json
	engine := policy.NewPolicyEngine() // Loads default embedded

	tests := []struct {
		name          string
		action        string
		ctx           map[string]interface{}
		expectedPerm  string
		expectedScope string
	}{
		{
			name:          "Assign Resource Owner (No Conditions)",
			action:        "assign_resource_owner",
			ctx:           map[string]interface{}{},
			expectedPerm:  "",
			expectedScope: "resource",
		},
		{
			name:          "Transfer Resource Owner (Standard)",
			action:        "transfer_resource_owner",
			ctx:           map[string]interface{}{"resource_type": "dashboard"},
			expectedPerm:  "resource.dashboard.transfer_owner",
			expectedScope: "resource",
		},
		{
			name:          "Assign Widget Viewer (Special Condition)",
			action:        "assign_resource_user_role",
			ctx:           map[string]interface{}{"resource_type": "dashboard_widget", "role": "viewer"},
			expectedPerm:  "resource.dashboard.add_widget_viewer",
			expectedScope: "parent",
		},
		{
			name:          "Assign Standard Member",
			action:        "assign_resource_user_role",
			ctx:           map[string]interface{}{"resource_type": "dashboard", "role": "editor"},
			expectedPerm:  "resource.dashboard.add_member",
			expectedScope: "resource",
		},
		{
			name:          "Delete Widget Viewer (Special Condition)",
			action:        "delete_resource_user_role",
			ctx:           map[string]interface{}{"resource_type": "dashboard_widget", "target_role_is_viewer": true},
			expectedPerm:  "resource.dashboard.add_widget_viewer",
			expectedScope: "parent",
		},
		{
			name:          "Delete System Member",
			action:        "delete_system_user_role",
			ctx:           nil,
			expectedPerm:  "platform.system.remove_member",
			expectedScope: "resource",
		},
		{
			name:          "Get User Roles Me (System)",
			action:        "get_user_roles_me",
			ctx:           map[string]interface{}{"scope": "system"},
			expectedPerm:  "platform.system.read",
			expectedScope: "resource",
		},
		{
			name:          "Get User Roles Me (Resource)",
			action:        "get_user_roles_me",
			ctx:           map[string]interface{}{"scope": "resource", "resource_type": "dashboard"},
			expectedPerm:  "resource.dashboard.read",
			expectedScope: "resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm, scope, err := engine.GetPermission(tt.action, tt.ctx)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedPerm, perm)
			assert.Equal(t, tt.expectedScope, scope)
		})
	}
}
