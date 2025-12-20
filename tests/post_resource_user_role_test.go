package tests

import "testing"

func TestPostResourceUserRole(t *testing.T) {
	// API: POST /user_roles/resources

	t.Run("assign resource editor role success and return 200", func(t *testing.T) {})
	t.Run("assign resource viewer role success and return 200", func(t *testing.T) {})
	t.Run("edit existing resource user role success and return 200", func(t *testing.T) {})
	t.Run("assign resource role invalid role and return 400", func(t *testing.T) {})
	t.Run("assign resource role missing resource info and return 400", func(t *testing.T) {})
	t.Run("assign resource role unauthorized and return 401", func(t *testing.T) {})
	t.Run("assign resource role forbidden (missing add_member permission) and return 403", func(t *testing.T) {})
	t.Run("assign resource role forbidden (editor trying to assign owner) and return 403", func(t *testing.T) {})
	t.Run("assign resource role forbidden (cannot downgrade last owner) and return 403", func(t *testing.T) {})
	t.Run("assign resource role forbidden (cannot upgrade last owner) and return 403", func(t *testing.T) {})
	t.Run("assign resource role internal error and return 500", func(t *testing.T) {})
}
