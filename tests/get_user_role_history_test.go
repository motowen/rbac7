package tests

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetUserRoleHistory(t *testing.T) {
	// API: GET /api/v1/user_roles/logs (with middleware)
	apiPath := "/api/v1/user_roles/logs"

	t.Run("get system history success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedHistory := []*model.UserRoleHistory{
			{ID: "h_1", Operation: "assign_owner", CallerID: "admin_1", Scope: "system", Namespace: "NS_1", CreatedAt: time.Now()},
		}
		mockRepo.On("FindHistory", mock.Anything, mock.MatchedBy(func(req model.GetUserRoleHistoryReq) bool {
			return req.Scope == "system" && req.Namespace == "NS_1"
		})).Return(expectedHistory, int64(1), nil)

		params := url.Values{}
		params.Add("scope", "system")
		params.Add("namespace", "NS_1")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "assign_owner")
		assert.Contains(t, rec.Body.String(), "\"total_count\":1")
	})

	t.Run("get resource history success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)

		expectedHistory := []*model.UserRoleHistory{
			{ID: "h_2", Operation: "assign_user_role", CallerID: "admin_1", Scope: "resource", ResourceID: "dash_1", ResourceType: "dashboard", CreatedAt: time.Now()},
		}
		mockRepo.On("FindHistory", mock.Anything, mock.MatchedBy(func(req model.GetUserRoleHistoryReq) bool {
			return req.Scope == "resource" && req.ResourceID == "dash_1" && req.ResourceType == "dashboard"
		})).Return(expectedHistory, int64(1), nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "dash_1")
		params.Add("resource_type", "dashboard")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "assign_user_role")
	})

	t.Run("get history with pagination success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedHistory := []*model.UserRoleHistory{
			{ID: "h_3", Operation: "delete_user_role", CallerID: "admin_1", Scope: "system", Namespace: "NS_1", CreatedAt: time.Now()},
		}
		mockRepo.On("FindHistory", mock.Anything, mock.MatchedBy(func(req model.GetUserRoleHistoryReq) bool {
			return req.Page == 2 && req.Size == 50
		})).Return(expectedHistory, int64(100), nil)

		params := url.Values{}
		params.Add("scope", "system")
		params.Add("namespace", "NS_1")
		params.Add("page", "2")
		params.Add("size", "50")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "\"page\":2")
		assert.Contains(t, rec.Body.String(), "\"size\":50")
		assert.Contains(t, rec.Body.String(), "\"total_count\":100")
	})

	t.Run("get history missing scope returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodGet, apiPath, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get system history missing namespace returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		path := apiPath + "?scope=system"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get resource history missing resource_id returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		path := apiPath + "?scope=resource&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get history unauthorized returns 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		path := apiPath + "?scope=system&namespace=NS_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("get system history forbidden returns 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "viewer_1", "NS_1", mock.Anything).Return(false, nil)

		path := apiPath + "?scope=system&namespace=NS_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "viewer_1"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("get resource history forbidden returns 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "viewer_1", "dash_1", "dashboard", mock.Anything).Return(false, nil)

		path := apiPath + "?scope=resource&resource_id=dash_1&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "viewer_1"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("get resource history with child_resource_ids success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "dash_1", "dashboard", mock.Anything).Return(true, nil)

		expectedHistory := []*model.UserRoleHistory{
			{ID: "h_4", Operation: "assign_viewer", CallerID: "admin_1", Scope: "resource", ResourceID: "widget_1", ResourceType: "dashboard_widget", CreatedAt: time.Now()},
			{ID: "h_5", Operation: "assign_user_role", CallerID: "admin_1", Scope: "resource", ResourceID: "dash_1", ResourceType: "dashboard", CreatedAt: time.Now()},
		}
		mockRepo.On("FindHistory", mock.Anything, mock.MatchedBy(func(req model.GetUserRoleHistoryReq) bool {
			return req.Scope == "resource" && req.ResourceID == "dash_1" && len(req.ChildResourceIDs) == 2
		})).Return(expectedHistory, int64(2), nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "dash_1")
		params.Add("resource_type", "dashboard")
		params.Add("child_resource_ids", "widget_1")
		params.Add("child_resource_ids", "widget_2")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "\"total_count\":2")
	})

	t.Run("get library_widget history success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: library_widget uses system scope check (namespace)
		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedHistory := []*model.UserRoleHistory{
			{ID: "h_6", Operation: "assign_viewers_batch", CallerID: "admin_1", Scope: "resource", ResourceID: "lw_1", ResourceType: "library_widget", CreatedAt: time.Now()},
		}
		mockRepo.On("FindHistory", mock.Anything, mock.MatchedBy(func(req model.GetUserRoleHistoryReq) bool {
			return req.Scope == "resource" && req.ResourceID == "lw_1" && req.ResourceType == "library_widget"
		})).Return(expectedHistory, int64(1), nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "lw_1")
		params.Add("resource_type", "library_widget")
		params.Add("namespace", "NS_1")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "assign_viewers_batch")
	})

	t.Run("get library_widget history forbidden returns 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "viewer_1", "NS_1", mock.Anything).Return(false, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "lw_1")
		params.Add("resource_type", "library_widget")
		params.Add("namespace", "NS_1")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "viewer_1"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}
