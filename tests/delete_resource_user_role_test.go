package tests

import "testing"

func TestDeleteResourceUserRole(t *testing.T) {
	// API: DELETE /user_roles/resources

	t.Run("remove resource member success and return 200", func(t *testing.T) {})
	t.Run("remove resource member missing params and return 400", func(t *testing.T) {})
	t.Run("remove resource member unauthorized and return 401", func(t *testing.T) {})
	t.Run("remove resource member forbidden (missing remove_member permission) and return 403", func(t *testing.T) {})
	t.Run("remove resource member forbidden (cannot delete last owner) and return 403", func(t *testing.T) {})
	// Anti-enumeration (pick rule)
	t.Run("remove resource member forbidden should not reveal existence and return 403 even if target not found", func(t *testing.T) {})
	// Idempotency / repeated delete (define rule: 200)
	t.Run("remove resource member twice should be idempotent and return 200", func(t *testing.T) {})
	t.Run("remove resource member internal error and return 500", func(t *testing.T) {})
}
