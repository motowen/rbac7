package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostSystemUserRole(t *testing.T) {
	apiPath := "/api/v1/user_roles"

	t.Run("assign system admin role success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		// Service: check owner
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		// Service: upsert
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Role == "admin" && r.UserID == "u_2"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: "NS_1", Scope: "system"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign system viewer role success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Role == "viewer" && r.UserID == "u_3"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "u_3", Role: "viewer", Namespace: "NS_1", Scope: "system"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("edit existing system user role success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Role == "viewer" && r.UserID == "u_existing"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "u_existing", Role: "viewer", Namespace: "NS_1", Scope: "system"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("edit system role forbidden (cannot downgrade last owner) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)

		currentOwner := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(currentOwner, nil)
		mockRepo.On("CountSystemOwners", mock.Anything, "NS_1").Return(int64(1), nil)

		reqBody := model.SystemUserRole{UserID: "owner_1", Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign system owner role and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "owner", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system role invalid role value and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "god_mode", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system role forbidden (caller not owner/admin) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "NS_1", mock.Anything).Return(false, nil)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "viewer", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "u_common"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign system role missing namespace and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: ""}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system role missing user_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.SystemUserRole{UserID: "", Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system role unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign system role internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.Anything).Return(errors.New("db error"))

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("assign system role auth check db error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(false, errors.New("db disconnect"))

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
