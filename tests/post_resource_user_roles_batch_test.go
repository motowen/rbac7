package tests

import (
	"encoding/json"
	"errors"
	"net/http"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostResourceUserRolesBatch(t *testing.T) {
	t.Run("assign multiple users admin role success", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch", h.PostResourceUserRolesBatch)

		// Permission Check
		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)

		// Expect bulk upsert
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2 && roles[0].Role == "admin" && roles[0].Scope == model.ScopeResource
		})).Return(&model.BatchUpsertResult{SuccessCount: 2, FailedCount: 0}, nil)

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{"u_2", "u_3"},
			Role:         "admin",
			ResourceID:   "dash_1",
			ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 0, result.FailedCount)
	})

	t.Run("assign viewer role success", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_viewer", h.PostResourceUserRolesBatch)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 1 && roles[0].Role == "viewer"
		})).Return(&model.BatchUpsertResult{SuccessCount: 1, FailedCount: 0}, nil)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_3"}, Role: "viewer", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_viewer", reqBody, map[string]string{"x-user-id": "admin_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign editor role success", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_editor", h.PostResourceUserRolesBatch)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2 && roles[0].Role == "editor"
		})).Return(&model.BatchUpsertResult{SuccessCount: 2, FailedCount: 0}, nil)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_4", "u_5"}, Role: "editor", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_editor", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("fail validation empty user_ids", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch", h.PostResourceUserRolesBatch)

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{},
			Role:         "admin",
			ResourceID:   "dash_1",
			ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign owner role return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_owner", h.PostResourceUserRolesBatch)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "owner", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_owner", reqBody, map[string]string{"x-user-id": "admin_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign invalid role return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_invalid", h.PostResourceUserRolesBatch)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "god_mode", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_invalid", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign forbidden caller not owner/admin return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_forbidden", h.PostResourceUserRolesBatch)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "u_common", "dash_1", "dashboard", mock.Anything).Return(false, nil)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "viewer", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_forbidden", reqBody, map[string]string{"x-user-id": "u_common", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign missing resource_id return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_no_res", h.PostResourceUserRolesBatch)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_no_res", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign unauthorized no auth header return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_401", h.PostResourceUserRolesBatch)

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_401", reqBody, map[string]string{})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign internal error return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_500", h.PostResourceUserRolesBatch)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_500", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("auth check db error return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_auth_error", h.PostResourceUserRolesBatch)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(false, errors.New("db disconnect"))

		reqBody := model.AssignResourceUserRolesReq{UserIDs: []string{"u_2"}, Role: "admin", ResourceID: "dash_1", ResourceType: "dashboard"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_auth_error", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	// Partial success/failure tests
	t.Run("partial success some users succeed some fail", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_partial", h.PostResourceUserRolesBatch)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)

		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 3
		})).Return(&model.BatchUpsertResult{
			SuccessCount: 2,
			FailedCount:  1,
			FailedUsers: []model.FailedUserInfo{
				{UserID: "u_owner", Reason: "owner role protected"},
			},
		}, nil)

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{"u_normal_1", "u_owner", "u_normal_2"},
			Role:         "admin",
			ResourceID:   "dash_1",
			ResourceType: "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_partial", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 1, result.FailedCount)
		assert.Len(t, result.FailedUsers, 1)
	})

	t.Run("partial success all users fail", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_all_fail", h.PostResourceUserRolesBatch)

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
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_all_fail", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 0, result.SuccessCount)
		assert.Equal(t, 2, result.FailedCount)
	})

	t.Run("widget viewer batch requires parent_resource_id", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_widget", h.PostResourceUserRolesBatch)

		reqBody := model.AssignResourceUserRolesReq{
			UserIDs:      []string{"u_2"},
			Role:         "viewer",
			ResourceID:   "widget_1",
			ResourceType: "dashboard_widget",
			// Missing ParentResourceID
		}
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_widget", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("widget viewer batch with parent_resource_id success", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/resources/batch_widget_ok", h.PostResourceUserRolesBatch)

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
		rec := PerformRequest(e, http.MethodPost, "/user_roles/resources/batch_widget_ok", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
