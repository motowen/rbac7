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
	t.Run("list scope=system but provide resource_type/resource_id and return 400", func(t *testing.T) {})
	t.Run("list scope=resource but provide namespace and return 400", func(t *testing.T) {})
	t.Run("list scope=resource missing only resource_id and return 400", func(t *testing.T) {})
	t.Run("list scope=resource resource_type/resource_id empty string and return 400", func(t *testing.T) {})
	t.Run("list members unauthorized and return 401", func(t *testing.T) {})
	t.Run("list system members forbidden (missing platform.system.get_member) and return 403", func(t *testing.T) {})
	t.Run("list resource members forbidden (missing resource get_member) and return 403", func(t *testing.T) {})
	t.Run("list members internal error and return 500", func(t *testing.T) {})
	// Anti-enumeration (pick a rule and test it)
	t.Run("list members forbidden should not reveal existence and return 403 even if target exists", func(t *testing.T) {})
	// Response correctness
	t.Run("list system members response all namespace are same as query", func(t *testing.T) {})
	t.Run("list resource members response all resource_type/resource_id are same as query", func(t *testing.T) {})
}
