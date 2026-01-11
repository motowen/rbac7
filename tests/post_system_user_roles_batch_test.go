package tests

import (
	"encoding/json"
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostUserRolesBatch(t *testing.T) {
	apiPath := "/api/v1/user_roles/batch"

	t.Run("assign multiple users admin role success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		// Service: check owner
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		// Service: bulk upsert
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2 && roles[0].Role == "admin" && roles[1].Role == "admin"
		})).Return(&model.BatchUpsertResult{SuccessCount: 2, FailedCount: 0}, nil)

		reqBody := model.AssignSystemUserRolesReq{
			UserIDs:   []string{"u_2", "u_3"},
			Role:      "admin",
			Namespace: "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 0, result.FailedCount)
	})

	t.Run("assign system viewer role success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 1 && roles[0].Role == "viewer"
		})).Return(&model.BatchUpsertResult{SuccessCount: 1, FailedCount: 0}, nil)

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_3"}, Role: "viewer", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign system dev_user role success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2 && roles[0].Role == "dev_user"
		})).Return(&model.BatchUpsertResult{SuccessCount: 2, FailedCount: 0}, nil)

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_4", "u_5"}, Role: "dev_user", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("fail validation empty user_ids", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignSystemUserRolesReq{
			UserIDs:   []string{},
			Role:      "admin",
			Namespace: "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign owner role return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_2"}, Role: "owner", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign invalid role return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_2"}, Role: "god_mode", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign forbidden caller not owner/admin return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "NS_1", mock.Anything).Return(false, nil)

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_2"}, Role: "viewer", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "u_common"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign missing namespace return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", Namespace: ""}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign unauthorized no x-user-id header return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign internal error return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("auth check db error return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(false, errors.New("db disconnect"))

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", Namespace: "NS_1"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("partial success some users succeed some fail", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 3
		})).Return(&model.BatchUpsertResult{
			SuccessCount: 2,
			FailedCount:  1,
			FailedUsers:  []model.FailedUserInfo{{UserID: "u_owner", Reason: "owner role protected"}},
		}, nil)

		reqBody := model.AssignSystemUserRolesReq{
			UserIDs:   []string{"u_normal_1", "u_owner", "u_normal_2"},
			Role:      "admin",
			Namespace: "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 1, result.FailedCount)
		assert.Len(t, result.FailedUsers, 1)
		assert.Equal(t, "u_owner", result.FailedUsers[0].UserID)
	})

	t.Run("partial success all users fail", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2
		})).Return(&model.BatchUpsertResult{
			SuccessCount: 0,
			FailedCount:  2,
			FailedUsers: []model.FailedUserInfo{
				{UserID: "u_owner_1", Reason: "owner role protected"},
				{UserID: "u_owner_2", Reason: "owner role protected"},
			},
		}, nil)

		reqBody := model.AssignSystemUserRolesReq{
			UserIDs:   []string{"u_owner_1", "u_owner_2"},
			Role:      "admin",
			Namespace: "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 0, result.SuccessCount)
		assert.Equal(t, 2, result.FailedCount)
		assert.Len(t, result.FailedUsers, 2)
	})

	t.Run("assign with user_type specified", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 1 && roles[0].UserType == "org"
		})).Return(&model.BatchUpsertResult{SuccessCount: 1, FailedCount: 0}, nil)

		reqBody := model.AssignSystemUserRolesReq{UserIDs: []string{"org_1"}, Role: "admin", Namespace: "NS_1", UserType: "org"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
