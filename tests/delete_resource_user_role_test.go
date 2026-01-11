package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDeleteResourceUserRole(t *testing.T) {
	// API: DELETE /api/v1/user_roles/resources (with middleware)

	t.Run("delete resource user role success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		// Service: owner check
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(false, nil)
		// Service: delete
		mockRepo.On("DeleteUserRole", mock.Anything, "", "u1", model.ScopeResource, "r1", "dashboard", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("delete resource user role missing user_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware may pass, validation fails in handler
		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete resource user role missing resource_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete resource user role missing resource_type and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware may pass through when no matching config (missing resource_type)
		// Handler validation will reject missing resource_type
		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("DeleteUserRole", mock.Anything, mock.Anything).Return(nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=r1", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete resource user role unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// No x-user-id header -> middleware returns 401
		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=r1&resource_type=dashboard", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("delete resource user role forbidden and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("delete resource user role forbidden (cannot remove owner) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission granted
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		// Service: target is owner
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(true, nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("delete resource user role internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "", "u1", model.ScopeResource, "r1", "dashboard", "caller").Return(errors.New("db error"))

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	// Dashboard Widget tests

	t.Run("delete dashboard_widget viewer success with parent_resource_id and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: check permission on parent dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		// Service: owner check
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "w1", "dashboard_widget", model.RoleResourceOwner).Return(false, nil)
		// Service: delete
		mockRepo.On("DeleteUserRole", mock.Anything, "", "u1", model.ScopeResource, "w1", "dashboard_widget", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=w1&resource_type=dashboard_widget&parent_resource_id=dash_1", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("delete dashboard_widget viewer missing parent_resource_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// No mocks needed - middleware should return 400 before any permission check
		// because parent_resource_required=true for dashboard_widget delete_viewer

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=w1&resource_type=dashboard_widget", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete dashboard_widget viewer forbidden on parent and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied on parent dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "dash_1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?user_id=u1&resource_id=w1&resource_type=dashboard_widget&parent_resource_id=dash_1", nil, map[string]string{
			"x-user-id": "caller",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}
