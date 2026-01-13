package tests

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetUserRolesList(t *testing.T) {
	// API: GET /api/v1/user_roles (with middleware)
	apiPath := "/api/v1/user_roles"

	t.Run("list system members success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", Namespace: "NS_1", Scope: "system"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Namespace == "NS_1" && f.Scope == "system"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "system")
		params.Add("namespace", "NS_1")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("list resource members success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "r1", "dashboard", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", ResourceID: "r1", ResourceType: "dashboard", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Scope == "resource" && f.ResourceID == "r1" && f.ResourceType == "dashboard"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "r1")
		params.Add("resource_type", "dashboard")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("list system members filtered by namespace success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_TARGET", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_target", Role: "admin", Namespace: "NS_TARGET"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Namespace == "NS_TARGET"
		})).Return(expectedRoles, nil)

		path := apiPath + "?scope=system&namespace=NS_TARGET"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_target")
	})

	t.Run("list resource members filtered by resource_type success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "r2", "dashboard", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_2", Role: "admin", ResourceID: "r2", ResourceType: "dashboard"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "r2")
		params.Add("resource_type", "dashboard")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_2")
	})

	t.Run("list dashboard_widget resource members success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "d_1", "dashboard", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", ResourceID: "dw_1", ResourceType: "dashboard_widget", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Scope == "resource" && f.ResourceID == "dw_1" && f.ResourceType == "dashboard_widget"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "dw_1")
		params.Add("resource_type", "dashboard_widget")
		params.Add("parent_resource_id", "d_1")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("list library_widget members success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", ResourceID: "lw_1", ResourceType: "library_widget", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.ResourceID == "lw_1" && f.ResourceType == "library_widget" && f.Scope == "resource"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "lw_1")
		params.Add("resource_type", "library_widget")
		params.Add("namespace", "NS_1")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("list members missing scope parameter and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware may pass, validation fails in handler
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodGet, apiPath, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list system members missing namespace parameter and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodGet, apiPath+"?scope=system", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list resource members missing resource params and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware may pass through when no matching config, validation fails in handler
		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{}, nil).Maybe()

		rec := PerformRequest(e, http.MethodGet, apiPath+"?scope=resource", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=system but provide resource_type/resource_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		path := apiPath + "?scope=system&namespace=NS1&resource_id=123"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=resource missing only resource_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware passes through for validation failure cases
		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{}, nil).Maybe()

		// Use 'dashboard' to match middleware config, missing resource_id triggers validation error
		path := apiPath + "?scope=resource&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=resource resource_type/resource_id empty string and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware passes through for validation failure cases
		mockRepo.On("HasAnyResourceRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{}, nil).Maybe()

		// Empty resource_id/type triggers validation error
		path := apiPath + "?scope=resource&resource_id=&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list members unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// No x-user-id header
		rec := PerformRequest(e, http.MethodGet, apiPath+"?scope=system&namespace=NS_1", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("list system members forbidden (missing platform.system.get_member) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_no_perm", "NS_1", mock.Anything).Return(false, nil)

		path := apiPath + "?scope=system&namespace=NS_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_no_perm"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("list resource members forbidden (missing resource get_member) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied (use 'dashboard' to match config)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "u_no", "r1", "dashboard", mock.Anything).Return(false, nil)

		path := apiPath + "?scope=resource&resource_id=r1&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_no"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("list members internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		path := apiPath + "?scope=system&namespace=NS_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("list system members response all namespace are same as query", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", Namespace: "NS_1"},
			{UserID: "u_2", Role: "admin", Namespace: "NS_1"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(expectedRoles, nil)

		path := apiPath + "?scope=system&namespace=NS_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "NS_1")
		assert.NotContains(t, rec.Body.String(), "ns_other")
	})

	t.Run("list resource members response all resource_type/resource_id are same as query", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "r1", "dashboard", mock.Anything).Return(true, nil)
		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", ResourceID: "r1", ResourceType: "dashboard"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(expectedRoles, nil)

		path := apiPath + "?scope=resource&resource_id=r1&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "dashboard")
	})
}
