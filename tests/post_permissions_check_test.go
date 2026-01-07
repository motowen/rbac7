package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostPermissionsCheck(t *testing.T) {
	// API: POST /permissions/check

	t.Run("check system permission allowed and return 200 true", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "", mock.Anything).Return(true, nil)

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("check system permission denied and return 200 false", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnySystemRole", mock.Anything, "user_1", "", mock.Anything).Return(false, nil)

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})

	t.Run("check system permission with namespace allowed and return 200 true", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS1", mock.Anything).Return(true, nil)

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
			"namespace":  "ns1",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("check resource permission allowed and return 200 true", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "r1", "dashboard", mock.Anything).Return(true, nil)

		payload := map[string]string{
			"permission":    "resource.dashboard.read",
			"scope":         "resource",
			"resource_id":   "r1",
			"resource_type": "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("check resource permission denied and return 200 false", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "r1", "dashboard", mock.Anything).Return(false, nil)

		payload := map[string]string{
			"permission":    "resource.dashboard.read",
			"scope":         "resource",
			"resource_id":   "r1",
			"resource_type": "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})

	t.Run("check permission missing permission field and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		payload := map[string]string{
			"scope": "system",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "u1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("check permission missing scope field and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		payload := map[string]string{
			"permission": "p1",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "u1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("check resource permission missing resource_id/type and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		payload := map[string]string{
			"permission": "p1",
			"scope":      "resource",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "u1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("check permission invalid scope value and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		payload := map[string]string{
			"permission": "p1",
			"scope":      "invalid",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "u1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("check resource permission resource_type/resource_id empty string and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		payload := map[string]string{
			"permission":    "p1",
			"scope":         "resource",
			"resource_id":   "",
			"resource_type": "",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "u1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("check permission unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		payload := map[string]string{
			"permission": "p1",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, nil) // No Auth
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("check permission internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "", mock.Anything).Return(false, errors.New("db error"))

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	// Library Widget Permission Check Tests
	t.Run("check library_widget read permission allowed", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "viewer_1", "lw_1", "library_widget", mock.Anything).Return(true, nil)

		payload := map[string]string{
			"permission":    "resource.library_widget.read",
			"scope":         "resource",
			"resource_id":   "lw_1",
			"resource_type": "library_widget",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "viewer_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("check library_widget read permission denied", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/permissions/check", h.PostPermissionsCheck)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "lw_1", "library_widget", mock.Anything).Return(false, nil)

		payload := map[string]string{
			"permission":    "resource.library_widget.read",
			"scope":         "resource",
			"resource_id":   "lw_1",
			"resource_type": "library_widget",
		}
		rec := PerformRequest(e, http.MethodPost, "/permissions/check", payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})
}
