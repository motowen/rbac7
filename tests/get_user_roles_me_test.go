package tests

import "testing"

func TestGetUserRolesMe(t *testing.T) {
	// API: GET /user_roles/me

	t.Run("get current user system roles success and return 200", func(t *testing.T) {})
	t.Run("get current user resource roles success and return 200", func(t *testing.T) {})
	t.Run("get user roles missing scope parameter and return 400", func(t *testing.T) {})
	t.Run("get resource roles missing resource_type parameter and return 400", func(t *testing.T) {})
	t.Run("get user roles invalid scope value and return 400", func(t *testing.T) {})
	t.Run("get user roles unauthorized (no token) and return 401", func(t *testing.T) {})
	t.Run("get user roles forbidden (missing system read permission) and return 403", func(t *testing.T) {})
	t.Run("get user roles forbidden (missing resource read permission) and return 403", func(t *testing.T) {})
	t.Run("get user roles internal server error and return 500", func(t *testing.T) {})

	// Response correctness (not only status code)
	t.Run("get user roles should only return roles of current user", func(t *testing.T) {})
}
