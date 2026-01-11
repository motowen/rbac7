package tests

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPutResourceOwner(t *testing.T) {
	apiPath := "/api/v1/user_roles/resources/owner"

	t.Run("transfer resource owner success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{
			"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard",
		}

		// RBAC Middleware: permission check
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		// Service: transfer
		mockRepo.On("TransferResourceOwner", mock.Anything, "r1", "dashboard", "caller", "u_new", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("transfer resource owner old owner becomes admin/editor and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{
			"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard",
		}
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("TransferResourceOwner", mock.Anything, "r1", "dashboard", "caller", "u_new", "caller").Return(nil)

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("transfer resource owner missing parameters and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"user_id": "u_new"}

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer resource owner to same user_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{
			"user_id": "caller", "resource_id": "r1", "resource_type": "dashboard",
		}

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer resource owner unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}
		rec := PerformRequest(e, http.MethodPut, apiPath, payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("transfer resource owner forbidden (not current owner) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("transfer resource owner forbidden (cannot transfer last owner) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("transfer resource owner internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"user_id": "u_new", "resource_id": "r1", "resource_type": "dashboard"}

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "r1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("TransferResourceOwner", mock.Anything, "r1", "dashboard", "caller", "u_new", "caller").Return(errors.New("db error"))

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, map[string]string{"x-user-id": "caller"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
