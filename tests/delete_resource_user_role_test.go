package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDeleteResourceUserRole(t *testing.T) {
	// API: DELETE /resource_roles

	t.Run("delete resource user role success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "", "u1", model.ScopeResource, "r1", "dashboard", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("delete resource user role missing user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete resource user role missing resource_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?user_id=u1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete resource user role missing resource_type and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete resource user role unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?user_id=u1&resource_id=r1&resource_type=dashboard", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("delete resource user role forbidden and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("delete resource user role forbidden (cannot remove owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		// Target is owner
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(true, nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("delete resource user role internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/resource_roles", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "", "u1", model.ScopeResource, "r1", "dashboard", "caller").Return(errors.New("db error"))

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/resource_roles?user_id=u1&resource_id=r1&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
