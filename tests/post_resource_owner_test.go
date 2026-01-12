package tests

import (
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostResourceOwner(t *testing.T) {
	apiPath := "/api/v1/user_roles/resources/owner"

	t.Run("assign resource owner success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// No user_id in payload, caller is implied owner
		payload := map[string]string{
			"resource_id": "r1", "resource_type": "dashboard",
		}

		// Expect Count Check
		mockRepo.On("CountResourceOwners", mock.Anything, "r1", "dashboard").Return(int64(0), nil)

		// Expect assignment
		// UserID == "caller"
		mockRepo.On("CreateUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.UserID == "caller" && r.Role == model.RoleResourceOwner && r.ResourceID == "r1" && r.Namespace == ""
		})).Return(nil)

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign resource owner missing resource_id/type and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Missing resource_id/type. user_id optional/ignored.
		payload := map[string]string{"foo": "bar"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign resource owner unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"resource_id": "r1", "resource_type": "dashboard"}
		// No x-user-id header
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign resource owner already exists (conflict) and return 409", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"resource_id": "r1", "resource_type": "dashboard"}

		// Repo returns Count > 0
		mockRepo.On("CountResourceOwners", mock.Anything, "r1", "dashboard").Return(int64(1), nil)

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("assign resource owner internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]string{"resource_id": "r1", "resource_type": "dashboard"}

		// Repo returns Count -> 0
		mockRepo.On("CountResourceOwners", mock.Anything, "r1", "dashboard").Return(int64(0), nil)

		// Repo returns generic error
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(errors.New("db fail"))

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{
			"x-user-id": "caller", "authentication": "t",
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
