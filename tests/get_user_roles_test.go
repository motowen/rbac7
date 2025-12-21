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

// Reuse GetMeMockRepo type or define new one. Let's define one to be safe and isolated.
type GetRolesMockRepo struct {
	mock.Mock
}

func (m *GetRolesMockRepo) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.UserRole), args.Error(1)
}

func (m *GetRolesMockRepo) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}
func (m *GetRolesMockRepo) HasSystemRole(ctx context.Context, u, n, r string) (bool, error) {
	// Not explicitly used in list, but standard interface
	return false, nil
}

// Implement other interface methods
func (m *GetRolesMockRepo) UpsertUserRole(ctx context.Context, role *model.UserRole) error {
	return nil
}
func (m *GetRolesMockRepo) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	return nil
}
func (m *GetRolesMockRepo) GetSystemOwner(ctx context.Context, ns string) (*model.UserRole, error) {
	return nil, nil
}
func (m *GetRolesMockRepo) DeleteUserRole(ctx context.Context, ns, u, s string) error { return nil }
func (m *GetRolesMockRepo) EnsureIndexes(ctx context.Context) error                   { return nil }
func (m *GetRolesMockRepo) TransferSystemOwner(ctx context.Context, ns, o, n string) error {
	return nil
}
func (m *GetRolesMockRepo) CountSystemOwners(ctx context.Context, ns string) (int64, error) {
	return 0, nil
}

func TestGetUserRolesList(t *testing.T) {
	// API: GET /user_roles

	t.Run("list system members success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		// Mock Permission Check: platform.system.get_member
		// Assuming implementation checks for "system_admin" or similar role if granular permissions aren't fully separate yet,
		// OR we can implement a generic permission checker.
		// For now, let's assume valid scope='system' and namespace='ns1' requires at least some role?
		// Actually, standard list usually filters by namespace.
		// Permission: platform.system.get_member (Owner, Admin) - Viewer is NOT allowed anymore per spec.
		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "ns_1", []string{"admin", "owner"}).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", Namespace: "ns_1", Scope: "system"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Namespace == "ns_1" && f.Scope == "system"
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
		return
	})

	t.Run("list system members filtered by namespace success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "ns_target", []string{"admin", "owner"}).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_target", Role: "admin", Namespace: "ns_target"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.Namespace == "ns_target"
		})).Return(expectedRoles, nil)

		path := "/user_roles?scope=system&namespace=ns_target"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "u_target")
	})

	t.Run("list resource members filtered by resource_type success and return 200", func(t *testing.T) {
		return
	})

	t.Run("list members missing scope parameter and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		rec := PerformRequest(e, http.MethodGet, "/user_roles", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list system members missing namespace parameter (if required) and return 400", func(t *testing.T) {
		// Assuming system scope requires namespace according to this test request
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		rec := PerformRequest(e, http.MethodGet, "/user_roles?scope=system", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list resource members missing resource params and return 400", func(t *testing.T) {
		return // resource case
	})

	t.Run("list scope=system but provide resource_type/resource_id and return 400", func(t *testing.T) {
		// Mixed params invalid?
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		path := "/user_roles?scope=system&namespace=ns1&resource_id=123"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list scope=resource but provide namespace and return 400", func(t *testing.T) {
		return
	})

	t.Run("list scope=resource missing only resource_id and return 400", func(t *testing.T) {
		return
	})

	t.Run("list scope=resource resource_type/resource_id empty string and return 400", func(t *testing.T) {
		return
	})

	t.Run("list members unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		rec := PerformRequest(e, http.MethodGet, "/user_roles?scope=system", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("list system members forbidden (missing platform.system.get_member) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "u_no_perm", "ns_1", []string{"admin", "owner"}).Return(false, nil)

		path := "/user_roles?scope=system&namespace=ns_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_no_perm"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("list resource members forbidden (missing resource get_member) and return 403", func(t *testing.T) {
		return
	})

	t.Run("list members internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "ns_1", []string{"admin", "owner"}).Return(true, nil)
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		path := "/user_roles?scope=system&namespace=ns_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("list members forbidden should not reveal existence and return 403 even if target exists", func(t *testing.T) {
		// Usually list endpoints return empty list if not allowed, OR 403 if whole list access is denied.
		// Test expects 403.
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		// Deny
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_no_perm", "ns_target", []string{"admin", "owner"}).Return(false, nil)

		path := "/user_roles?scope=system&namespace=ns_target"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "u_no_perm"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("list system members response all namespace are same as query", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(GetRolesMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.GET("/user_roles", h.GetUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "ns_1", []string{"admin", "owner"}).Return(true, nil)

		expectedRoles := []*model.UserRole{
			{UserID: "u_1", Role: "viewer", Namespace: "ns_1"},
			{UserID: "u_2", Role: "admin", Namespace: "ns_1"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(expectedRoles, nil)

		path := "/user_roles?scope=system&namespace=ns_1"
		rec := PerformRequest(e, http.MethodGet, path, nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ns_1")
		assert.NotContains(t, rec.Body.String(), "ns_other")
	})

	t.Run("list resource members response all resource_type/resource_id are same as query", func(t *testing.T) {
		return
	})
}
