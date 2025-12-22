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

func TestPutResourceOwner(t *testing.T) {
	// API: PUT /user_roles/resources/owner

	t.Run("transfer resource owner success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{
			"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard",
		}

		// Permission check - No Namespace ("") as per update
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "", "r1", "dashboard", mock.Anything).Return(true, nil)
		// Repo Transfer - No Namespace ("")
		mockRepo.On("TransferResourceOwner", mock.Anything, "", "r1", "dashboard", "caller", "u_new", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("transfer resource owner old owner becomes admin/editor and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{
			"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard",
		}
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("TransferResourceOwner", mock.Anything, "", "r1", "dashboard", "caller", "u_new", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("transfer resource owner missing parameters and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{"user_id": "u_new"}

		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer resource owner to same user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{
			"user_id": "caller", "resource_id": "r1", "resource_type": "dashboard",
		}

		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer resource owner unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}
		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("transfer resource owner forbidden (not current owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}

		// Permission check fails
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "", "r1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("transfer resource owner forbidden (cannot transfer last owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}

		// Permission check fails
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "", "r1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("transfer resource owner internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/api/v1/user_roles/resources/owner", h.PutResourceOwner)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("TransferResourceOwner", mock.Anything, "", "r1", "dashboard", "caller", "u_new", "caller").Return(errors.New("db error"))

		rec := PerformRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
