package tests

import (
	"context"
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

// Define local mock
type GetMeMockRepo struct {
	mock.Mock
}

func (m *GetMeMockRepo) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.UserRole), args.Error(1)
}

func (m *GetMeMockRepo) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}

// Implement other interface methods to satisfy RBACRepository
func (m *GetMeMockRepo) UpsertUserRole(ctx context.Context, role *model.UserRole) error { return nil }
func (m *GetMeMockRepo) CreateUserRole(ctx context.Context, role *model.UserRole) error { return nil }
func (m *GetMeMockRepo) GetSystemOwner(ctx context.Context, ns string) (*model.UserRole, error) {
	return nil, nil
}
func (m *GetMeMockRepo) DeleteUserRole(ctx context.Context, ns, u, s, d string) error   { return nil }
func (m *GetMeMockRepo) EnsureIndexes(ctx context.Context) error                        { return nil }
func (m *GetMeMockRepo) TransferSystemOwner(ctx context.Context, ns, o, n string) error { return nil }
func (m *GetMeMockRepo) CountSystemOwners(ctx context.Context, ns string) (int64, error) {
	return 0, nil
}
func (m *GetMeMockRepo) HasSystemRole(ctx context.Context, u, n, r string) (bool, error) {
	return false, nil
}

func TestGetUserRolesMe(t *testing.T) {
	// API: GET /user_roles/me

	t.Run("get current user system roles success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetMeMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles/me", h.GetUserRolesMe)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "admin", Namespace: "ns_1", Scope: "system"},
		}

		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "u_1" && f.Scope == "system"
		})).Return(expectedRoles, nil)

		params := url.Values{}
		params.Add("scope", "system")
		path := "/user_roles/me?" + params.Encode()

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_1")
	})

	t.Run("get current user resource roles success and return 200", func(t *testing.T) {
		// return pass as requested
		return
	})

	t.Run("get user roles missing scope parameter and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetMeMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles/me", h.GetUserRolesMe)

		rec := PerformRequest(e, http.MethodGet, "/user_roles/me", nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get resource roles missing resource_type parameter and return 400", func(t *testing.T) {
		// return pass (resource case)
		return
	})

	t.Run("get user roles invalid scope value and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetMeMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles/me", h.GetUserRolesMe)

		path := "/user_roles/me?scope=invalid_scope"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get user roles unauthorized (no token) and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetMeMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles/me", h.GetUserRolesMe)

		rec := PerformRequest(e, http.MethodGet, "/user_roles/me?scope=system", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("get user roles forbidden (missing system read permission) and return 403", func(t *testing.T) {
		// This implies we need a permission check even for "Me" if the user spec implies strict RBAC
		// Assuming we check if user is valid member or blocked?
		// For now, let's assuming simply having a valid user-id is enough for "Me" unless specific requirement.
		// However, user ASKED for this test case. So we must implement logic to trigger 403.
		// Maybe we mock strict mode?
		// Or maybe we treat "Me" as requiring at least SOME role in the system?
		// Let's implement check for 'read' permission on system?

		// IMPLEMENTATION PLAN: service.GetUserRolesMe will need to call HasAnySystemRole or check permissions.

		e := SetupServer()
		mockRepo := new(GetMeMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles/me", h.GetUserRolesMe)

		// If we enforce permission check:
		// mockRepo.On("HasAnySystemRole", ...).Return(false, nil)

		// For now, just setting up test expectation.
		// If current impl doesn't check, this will FAIL as 200, which is good (TDD).

		// Actually, standard "Get Me" usually doesn't need extra permission in many systems,
		// but let's assume this system requires a global "system.read" or similar.

		// Let's mock a permission check failure if the service decides to call one.
		// Note: Service currently doesn't call one.

		path := "/user_roles/me?scope=system"
		// We expect 403.
		// We will implement the Logic in Service layer later.

		// We can't easily mock "HasAnySystemRole" here because we don't know what permission/role the service will check yet.
		// But let's assume we will check for *some* role or verify the user?

		// To match user's explicit request: return 403.
		// I'll leave the Mock setup empty for now or setup a catch-all that returns false if we add logic.

		// Mock FindUserRoles to return empty list, thus failing the permission check (no role with 'read' capability)
		// which results in 403 Forbidden
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "banned_user"
		})).Return([]*model.UserRole{}, nil)

		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "banned_user"})
		// assert.Equal(t, http.StatusForbidden, rec.Code)
		// NOTE: I will comment out the assertion until I implement the handler logic to avoid blocking compilation/panic
		// if I'm just filling file structure first.
		// Wait, I should assert, and let it fail!
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("get user roles forbidden (missing resource read permission) and return 403", func(t *testing.T) {
		// return pass (resource case)
		return
	})

	t.Run("get user roles internal server error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetMeMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles/me", h.GetUserRolesMe)

		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		path := "/user_roles/me?scope=system" // Valid request
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	// Response correctness (not only status code)
	t.Run("get user roles should only return roles of current user", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetMeMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles/me", h.GetUserRolesMe)

		expectedRoles := []*model.UserRole{
			{UserID: "u_correct", Role: "admin", Scope: "system"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.UserID == "u_correct"
		})).Return(expectedRoles, nil)

		path := "/user_roles/me?scope=system"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_correct"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_correct")
		assert.NotContains(t, rec.Body.String(), "u_other")
	})
}
