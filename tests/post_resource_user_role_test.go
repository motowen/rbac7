package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostResourceUserRole(t *testing.T) {
	// API: POST /api/v1/user_roles/resources (with middleware)
	apiPath := "/api/v1/user_roles/resources"

	t.Run("assign resource user role success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := model.ResourceUserRole{
			UserID: "u1", Role: "editor", ResourceID: "r1", ResourceType: "dashboard",
		}

		// RBAC Middleware: permission check
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)

		// Service: owner check
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(false, nil)

		// Service: upsert role
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.UserID == "u1" && r.Role == "editor" && r.ResourceID == "r1" && r.Namespace == ""
		})).Return(nil)

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign resource user role missing parameters and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := model.ResourceUserRole{UserID: "u1"} // Missing resource info

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign resource user role invalid role and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := model.ResourceUserRole{
			UserID: "u1", Role: "inv", ResourceID: "r1", ResourceType: "dashboard",
		}

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign resource user role unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := model.ResourceUserRole{
			UserID: "u1", Role: "editor", ResourceID: "r1", ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign resource user role forbidden and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := model.ResourceUserRole{
			UserID: "u1", Role: "editor", ResourceID: "r1", ResourceType: "dashboard",
		}

		// RBAC Middleware: permission check fails
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign resource user role forbidden (target is owner) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := model.ResourceUserRole{
			UserID: "u1", Role: "editor", ResourceID: "r1", ResourceType: "dashboard",
		}

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		// Target is owner
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(true, nil)

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign resource user role internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := model.ResourceUserRole{
			UserID: "u1", Role: "editor", ResourceID: "r1", ResourceType: "dashboard",
		}

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasResourceRole", mock.Anything, "u1", "r1", "dashboard", model.RoleResourceOwner).Return(false, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.Anything).Return(errors.New("db fail"))

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
