package tests

import "testing"

func TestPostPermissionsCheck(t *testing.T) {
	// API: POST /permissions/check

	t.Run("check system permission allowed and return 200 true", func(t *testing.T) {})
	t.Run("check system permission denied and return 200 false", func(t *testing.T) {})
	t.Run("check system permission with namespace allowed and return 200 true", func(t *testing.T) {})
	t.Run("check resource permission allowed and return 200 true", func(t *testing.T) {})
	t.Run("check resource permission denied and return 200 false", func(t *testing.T) {})
	t.Run("check permission missing permission field and return 400", func(t *testing.T) {})
	t.Run("check permission missing scope field and return 400", func(t *testing.T) {})
	t.Run("check resource permission missing resource_id/type and return 400", func(t *testing.T) {})
	t.Run("check permission invalid scope value and return 400", func(t *testing.T) {})
	t.Run("check resource permission resource_type/resource_id empty string and return 400", func(t *testing.T) {})
	t.Run("check permission unauthorized and return 401", func(t *testing.T) {})
	t.Run("check permission internal error and return 500", func(t *testing.T) {})
}
