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

func TestPostResourceUserRole(t *testing.T) {
	// API: POST /resource_roles

	t.Run("assign resource editor role success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)

		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "editor"}

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "NS", "r", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.UserID == "u1" && r.Role == "editor"
		})).Return(nil)

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign resource viewer role success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)

		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "viewer"}
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "NS", "r", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.Anything).Return(nil)

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("edit existing resource user role success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)

		// Same as create/upsert
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "viewer"}
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "NS", "r", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.Anything).Return(nil)

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign resource role invalid role and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "bad_role"}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign resource role missing resource info and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "role": "editor"}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign resource role unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "editor"}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign resource role forbidden (missing add_member permission) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "editor"}
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(false, nil)
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign resource role forbidden (editor trying to assign owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "owner"}
		// Role "owner" validation happens before permission check in logic
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign resource role forbidden (cannot downgrade last owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)

		// Target is owner, trying to set to editor
		payload := map[string]string{"user_id": "u_owner", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "editor"}
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u_owner", "NS", "r", "dashboard", model.RoleResourceOwner).Return(true, nil)

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign resource role forbidden (cannot upgrade last owner) and return 403", func(t *testing.T) {
		// This case is actually same as "editor trying to assign owner".
		// If we try to assign "owner" role via this API, it is forbidden regardless of who we target.
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "owner"}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign resource role internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources", h.PostResourceUserRoles)
		payload := map[string]string{"user_id": "u1", "namespace": "NS", "resource_id": "r", "resource_type": "dashboard", "role": "editor"}
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "NS", "r", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "NS", "r", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.Anything).Return(errors.New("fail"))
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources", payload, map[string]string{"x-user-id": "caller", "authentication": "t"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
