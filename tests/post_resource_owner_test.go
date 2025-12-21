package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostResourceOwner(t *testing.T) {
	// API: POST /user_roles/resources/owner

	t.Run("assign resource owner success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources/owner", h.PostResourceOwner)

		// Namespace removed
		payload := map[string]string{
			"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard",
		}

		// Expect assignment
		// Namespace is empty string ""
		mockRepo.On("CreateUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.UserID == "u_new" && r.Role == model.RoleResourceOwner && r.ResourceID == "r1" && r.Namespace == ""
		})).Return(nil)

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign resource owner missing resource_id/type and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources/owner", h.PostResourceOwner)

		// Missing resource_id/type
		payload := map[string]string{"user_id": "u_new"}

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign resource owner unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources/owner", h.PostResourceOwner)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dash"}
		// No x-user-id header
		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources/owner", payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign resource owner already exists (conflict) and return 409", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources/owner", h.PostResourceOwner)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dash"}

		// Repo returns ErrDuplicate
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(repository.ErrDuplicate)

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("assign resource owner internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/api/v1/user_roles/resources/owner", h.PostResourceOwner)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dash"}

		// Repo returns generic error
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(errors.New("db fail"))

		rec := PerformRequest(e, http.MethodPost, "/api/v1/user_roles/resources/owner", payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
