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
	"go.mongodb.org/mongo-driver/mongo"
)

func TestDeleteResourceUserRole(t *testing.T) {
	// API: DELETE /resource_roles

	t.Run("remove resource member success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u_target", "NS", "r", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS", "u_target", model.ScopeResource, "r", "dashboard", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS&user_id=u_target&resource_id=r&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("remove resource member missing params and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("remove resource member unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS&user_id=u&resource_id=r&resource_type=dashboard", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("remove resource member forbidden (missing remove_member permission) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS&user_id=u&resource_id=r&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove resource member forbidden (cannot delete last owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u_owner", "NS", "r", "dashboard", model.RoleResourceOwner).Return(true, nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS&user_id=u_owner&resource_id=r&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove resource member forbidden should not reveal existence and return 403 even if target not found", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		// Caller has NO permission
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(false, nil)

		// Should NOT check if target exists, just return 403
		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS&user_id=u_ghost&resource_id=r&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove resource member twice should be idempotent and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u_target", "NS", "r", "dashboard", model.RoleResourceOwner).Return(false, nil)
		// Return ErrNoDocuments treated as success
		mockRepo.On("DeleteUserRole", mock.Anything, "NS", "u_target", model.ScopeResource, "r", "dashboard", "caller").Return(mongo.ErrNoDocuments)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS&user_id=u_target&resource_id=r&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("remove resource member internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/api/v1/user_roles/resources", h.DeleteResourceUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u_target", "NS", "r", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS", "u_target", model.ScopeResource, "r", "dashboard", "caller").Return(errors.New("db fail"))

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=NS&user_id=u_target&resource_id=r&resource_type=dashboard", nil, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
