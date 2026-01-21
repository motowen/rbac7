package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestDeleteSystemUserRole(t *testing.T) {
	apiPath := "/api/v1/user_roles"

	t.Run("remove system member success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		// Service: check if target is owner
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		// Service: delete
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_2", "system", "", "", "", "owner_1").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?namespace=NS_1&user_id=u_2", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("remove system member missing user_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?namespace=NS_1", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("remove system member missing namespace and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_2", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("remove system member unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// No x-user-id header
		rec := PerformRequest(e, http.MethodDelete, apiPath+"?namespace=NS_1&user_id=u_2", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("remove system member forbidden (cannot delete last owner) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)

		ownerRole := &model.UserRole{UserID: "u_target", Role: model.RoleSystemOwner}
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("CountSystemOwners", mock.Anything, "NS_1").Return(int64(1), nil)

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?namespace=NS_1&user_id=u_target", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove system member forbidden (missing delete permission) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "NS_1", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?namespace=NS_1&user_id=u_2", nil, map[string]string{"x-user-id": "u_common"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove system member twice should be idempotent and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_2", "system", "", "", "", "owner_1").Return(mongo.ErrNoDocuments)

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?namespace=NS_1&user_id=u_2", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("remove system member internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_2", "system", "", "", "", "owner_1").Return(errors.New("db error"))

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?namespace=NS_1&user_id=u_2", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
