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

func TestGetUserRolesMe(t *testing.T) {
	apiPath := "/api/v1/user_roles/me"

	t.Run("get current user system roles success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "admin", Namespace: "NS_1", Scope: "system"},
		}

		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "u_1" && f.Scope == "system"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "system")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("get current user resource roles success and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", ResourceID: "r1", ResourceType: "dashboard", Scope: "resource"},
		}

		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "u_1" && f.Scope == "resource" && f.ResourceType == "dashboard"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_type", "dashboard")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "viewer")
	})

	t.Run("get user roles missing scope parameter and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware passthrough for validation failures
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{}, nil).Maybe()

		rec := PerformRequest(e, http.MethodGet, apiPath, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get resource roles missing resource_type parameter and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{}, nil).Maybe()

		path := apiPath + "?scope=resource"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get system user roles having resource_type parameter and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{}, nil).Maybe()

		path := apiPath + "?scope=system&resource_type=dashboard"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get user roles invalid scope value and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{}, nil).Maybe()

		path := apiPath + "?scope=invalid_scope"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get user roles forbidden (missing system read permission) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Return empty roles => No read permission => 403
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "banned_user" && f.Scope == "system"
		})).Return([]*model.UserRole{}, nil)

		path := apiPath + "?scope=system"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "banned_user"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("get user roles forbidden (missing resource read permission) and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Return empty roles => No read permission => 403
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "u_banned" && f.Scope == "resource" && f.ResourceType == "dashboard"
		})).Return([]*model.UserRole{}, nil)

		params := url.Values{}
		params.Add("scope", "resource")
		params.Add("resource_type", "dashboard")
		path := apiPath + "?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_banned"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("get user roles unauthorized (no token) and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		rec := PerformRequest(e, http.MethodGet, apiPath+"?scope=system", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("get user roles internal server error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		path := apiPath + "?scope=system"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("get user roles should only return roles of current user", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		expectedRoles := []*model.UserRole{
			{UserID: "u_correct", Role: "admin", Scope: "system"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "u_correct"
		})).Return(expectedRoles, nil)

		path := apiPath + "?scope=system"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_correct"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_correct")
		assert.NotContains(t, rec.Body.String(), "u_other")
	})
}
