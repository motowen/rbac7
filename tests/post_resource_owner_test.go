package tests

import "testing"

func TestPostResourceOwner(t *testing.T) {
	// API: POST /user_roles/resources/owner

	t.Run("assign resource owner success and return 200", func(t *testing.T) {})
	t.Run("assign resource owner missing resource_id/type and return 400", func(t *testing.T) {})
	t.Run("assign resource owner unauthorized and return 401", func(t *testing.T) {})
	t.Run("assign resource owner forbidden (missing permission) and return 403", func(t *testing.T) {})
	t.Run("assign resource owner already exists (conflict) and return 409", func(t *testing.T) {})
	t.Run("assign resource owner internal error and return 500", func(t *testing.T) {})
}
