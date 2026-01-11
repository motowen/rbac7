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

func TestPostResourceUserRolesBatch(t *testing.T) {
	apiPath := "/api/v1/user_roles/resources/batch"

	t.Run("assign multiple users admin role success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)

		// Service: bulk upsert
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2 && roles[0].Role == "admin" && roles[0].Scope == model.ScopeResource
		})).Return(&model.BatchUpsertResult{SuccessCount: 2, FailedCount: 0}, nil)

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{"u_2", "u_3"},
			Role:         "admin",
			ResourceID:   "dash_1",
			ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 0, result.FailedCount)
	})

	t.Run("assign viewer role success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 1 && roles[0].Role == "viewer"
		})).Return(&model.BatchUpsertResult{SuccessCount: 1, FailedCount: 0}, nil)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_3"}, Role: "viewer", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign editor role success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2 && roles[0].Role == "editor"
		})).Return(&model.BatchUpsertResult{SuccessCount: 2, FailedCount: 0}, nil)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_4", "u_5"}, Role: "editor", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("fail validation empty user_ids", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{},
			Role:         "admin",
			ResourceID:   "dash_1",
			ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign owner role return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "owner", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign invalid role return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "god_mode", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign forbidden caller not owner/admin return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnyResourceRole", mock.Anything, "u_common", "dash_1", "dashboard", mock.Anything).Return(false, nil)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "viewer", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "u_common"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign missing resource_id return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign unauthorized no x-user-id header return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign internal error return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("auth check db error return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(false, errors.New("db disconnect"))

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("partial success some users succeed some fail", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 3
		})).Return(&model.BatchUpsertResult{
			SuccessCount: 2,
			FailedCount:  1,
			FailedUsers:  []model.FailedUserInfo{{UserID: "u_owner", Reason: "owner role protected"}},
		}, nil)

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{"u_normal_1", "u_owner", "u_normal_2"},
			Role:         "admin",
			ResourceID:   "dash_1",
			ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 1, result.FailedCount)
		assert.Len(t, result.FailedUsers, 1)
	})

	t.Run("partial success all users fail", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
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

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{"u_owner_1", "u_owner_2"},
			Role:         "admin",
			ResourceID:   "dash_1",
			ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 0, result.SuccessCount)
		assert.Equal(t, 2, result.FailedCount)
	})

	t.Run("widget viewer batch requires parent_resource_id", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{"u_2"},
			Role:         "viewer",
			ResourceID:   "widget_1",
			ResourceType: "dashboard_widget",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("widget viewer batch with parent_resource_id success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Permission checked on parent dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.Anything).Return(&model.BatchUpsertResult{SuccessCount: 1, FailedCount: 0}, nil)

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:          []string{"u_2"},
			Role:             "viewer",
			ResourceID:       "widget_1",
			ResourceType:     "dashboard_widget",
			ParentResourceID: "dash_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
