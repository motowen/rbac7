package tests

import "testing"

func TestPutResourceOwner(t *testing.T) {
	// API: PUT /user_roles/resources/owner

	t.Run("transfer resource owner success and return 200", func(t *testing.T) {})
	t.Run("transfer resource owner old owner becomes admin/editor and return 200", func(t *testing.T) {})
	t.Run("transfer resource owner missing parameters and return 400", func(t *testing.T) {})
	t.Run("transfer resource owner to same user_id and return 400", func(t *testing.T) {})
	t.Run("transfer resource owner unauthorized and return 401", func(t *testing.T) {})
	t.Run("transfer resource owner forbidden (not current owner) and return 403", func(t *testing.T) {})
	t.Run("transfer resource owner forbidden (cannot transfer last owner) and return 403", func(t *testing.T) {})
	t.Run("transfer resource owner internal error and return 500", func(t *testing.T) {})
}
