package tests

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Reuse GetMeMockRepo type or define new one. Let's define one to be safe and isolated.
// GetRolesMockRepo usage is replaced by shared MockRBACRepository in mock_repo.go

func TestGetUserRolesList(t *testing.T) {
	// API: GET /user_roles

	t.Run("list system members success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		// Mock Permission Check: platform.system.get_member
		// Assuming implementation checks for "system_admin" or similar role if granular permissions aren't fully separate yet,
		// OR we can implement a generic permission checker.
		// For now, let's assume valid scope='system' and namespace='ns1' requires at least some role?
		// Actually, standard list usually filters by namespace.
		// Permission: platform.system.get_member (Owner, Admin) - Viewer is NOT allowed anymore per spec.
		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", Namespace: "NS_1", Scope: "system"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Namespace == "NS_1" && f.Scope == "system"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "system")
		params.Add("namespace", "ns_1")
		path := "/user_roles?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("list resource members success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		// Permission Check
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
		path := "/user_roles?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("list system members filtered by namespace success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_TARGET", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_target", Role: "admin", Namespace: "NS_TARGET"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Namespace == "NS_TARGET"
		})).Return(expectedRoles, nil)

		path := "/user_roles?scope=system&namespace=ns_target"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_target")
	})

	t.Run("list resource members filtered by resource_type success and return 200", func(t *testing.T) {
		// As per handler logic, BOTH id and type are required.
		// Testing with both.
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "r2", "dashboard", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_2", Role: "admin", ResourceID: "r2", ResourceType: "dashboard"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_id", "r2")
		params.Add("resource_type", "dashboard")
		path := "/user_roles?" + params.Encode() // Filter by ID/Type

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_2")
	})

	t.Run("list members missing scope parameter and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		rec := PerformRequest(e, http.MethodGet, "/user_roles", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list system members missing namespace parameter (if required) and return 400", func(t *testing.T) {
		// Assuming system scope requires namespace according to this test request
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		rec := PerformRequest(e, http.MethodGet, "/user_roles?scope=system", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list resource members missing resource params and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		// Scope resource, but no ID/Type
		rec := PerformRequest(e, http.MethodGet, "/user_roles?scope=resource", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=system but provide resource_type/resource_id and return 400", func(t *testing.T) {
		// Mixed params invalid?
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		path := "/user_roles?scope=system&namespace=ns1&resource_id=123"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=resource but provide namespace and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		path := "/user_roles?scope=resource&namespace=ns1&resource_id=r1&resource_type=d1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=resource missing only resource_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		path := "/user_roles?scope=resource&resource_type=d1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=resource resource_type/resource_id empty string and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		path := "/user_roles?scope=resource&resource_id=&resource_type="
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list members unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		rec := PerformRequest(e, http.MethodGet, "/user_roles?scope=system", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("list system members forbidden (missing platform.system.get_member) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "u_no_perm", "NS_1", mock.Anything).Return(false, nil)

		path := "/user_roles?scope=system&namespace=ns_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_no_perm"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("list resource members forbidden (missing resource get_member) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "u_no", "r1", "d1", mock.Anything).Return(false, nil)

		path := "/user_roles?scope=resource&resource_id=r1&resource_type=d1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_no"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("list members internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		path := "/user_roles?scope=system&namespace=ns_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("list members forbidden should not reveal existence and return 403 even if target exists", func(t *testing.T) {
		// Usually list endpoints return empty list if not allowed, OR 403 if whole list access is denied.
		// Test expects 403.
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		// Deny
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_no_perm", "NS_TARGET", mock.Anything).Return(false, nil)

		path := "/user_roles?scope=system&namespace=ns_target"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_no_perm"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("list system members response all namespace are same as query", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS_1", mock.Anything).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", Namespace: "NS_1"},
			{UserID: "u_2", Role: "admin", Namespace: "NS_1"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(expectedRoles, nil)

		path := "/user_roles?scope=system&namespace=ns_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "NS_1")
		assert.NotContains(t, rec.Body.String(), "ns_other")
	})

	t.Run("list resource members response all resource_type/resource_id are same as query", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "admin_1", "r1", "dashboard", mock.Anything).Return(true, nil)
		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", ResourceID: "r1", ResourceType: "dashboard"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(expectedRoles, nil)

		path := "/user_roles?scope=resource&resource_id=r1&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "dashboard")
	})
}
