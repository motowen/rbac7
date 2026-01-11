package tests

import (
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPutSystemOwner(t *testing.T) {
	apiPath := "/api/v1/user_roles/owner"

	t.Run("transfer system owner old owner becomes admin (implied) and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		// Service: get owner and transfer
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "new_owner", "owner_1").Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "NS_1"}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("transfer system owner missing new user_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemOwnerUpsertRequest{UserID: "", Namespace: "NS_1"}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner missing namespace and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: ""}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner to same user_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemOwnerUpsertRequest{UserID: "owner_1", Namespace: "NS_1"}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "u", Namespace: "NS"}
		rec := PerformRequest(e, http.MethodPut, apiPath, reqBody, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("transfer system owner forbidden (caller not current owner) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnySystemRole", mock.Anything, "fake_owner", "NS_1", mock.Anything).Return(false, nil)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "NS_1"}
		headers := map[string]string{"x-user-id": "fake_owner"}

		rec := PerformRequest(e, http.MethodPut, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("transfer system owner internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "new_owner", "owner_1").Return(errors.New("db error"))

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "NS_1"}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, reqBody, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
