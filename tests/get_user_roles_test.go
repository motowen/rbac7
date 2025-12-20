package tests

import "testing"

func TestGetUserRolesList(t *testing.T) {
	// API: GET /user_roles

	t.Run("list system members success and return 200", func(t *testing.T) {})
	t.Run("list resource members success and return 200", func(t *testing.T) {})
	t.Run("list system members filtered by namespace success and return 200", func(t *testing.T) {})
	t.Run("list resource members filtered by resource_type success and return 200", func(t *testing.T) {})
	t.Run("list members missing scope parameter and return 400", func(t *testing.T) {})
	t.Run("list system members missing namespace parameter (if required) and return 400", func(t *testing.T) {})
	t.Run("list resource members missing resource params and return 400", func(t *testing.T) {})
	t.Run("list members unauthorized and return 401", func(t *testing.T) {})
	t.Run("list system members forbidden (missing platform.system.get_member) and return 403", func(t *testing.T) {})
	t.Run("list resource members forbidden (missing resource get_member) and return 403", func(t *testing.T) {})
	t.Run("list members internal error and return 500", func(t *testing.T) {})
}
