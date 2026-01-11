package tests

import (
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostSystemOwner(t *testing.T) {
	apiPath := "/api/v1/user_roles/owner"

	t.Run("moderator assign system owner success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: global scope check (empty namespace for global roles like moderator)
		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		// Service: create user role
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "u_1",
			Namespace: "ns_success",
		}
		headers := map[string]string{"x-user-id": "moderator_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("assign system owner with whitespace inputs success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware uses global scope (empty namespace)
		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		mockRepo.On("CreateUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Namespace == "NS_TRIM" && r.UserID == "u_trim"
		})).Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "  u_trim  ",
			Namespace: "  ns_trim  ",
		}
		headers := map[string]string{"x-user-id": "moderator_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("assign system owner missing namespace and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware may pass with empty namespace, validation fails in handler
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, "", mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "u_1",
			Namespace: "",
		}
		headers := map[string]string{"x-user-id": "moderator_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system owner missing user_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, "", mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "",
			Namespace: "ns",
		}
		headers := map[string]string{"x-user-id": "moderator_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system owner unauthorized (empty caller) and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// No x-user-id header -> middleware returns 401
		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns", UserID: "u_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign system owner forbidden (not moderator) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: global scope permission denied (empty namespace for global check)
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "", mock.Anything).Return(false, nil)

		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns", UserID: "u_1"}
		headers := map[string]string{"x-user-id": "u_common"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign system owner already exists (conflict) and return 409", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(repository.ErrDuplicate)

		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns_conflict", UserID: "u_1"}
		headers := map[string]string{"x-user-id": "moderator_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("assign system owner internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(errors.New("db disconnect"))

		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns_error", UserID: "u_1"}
		headers := map[string]string{"x-user-id": "moderator_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
