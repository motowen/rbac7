package tests

import (
	"context"
	"errors"
	"net/http"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type UserRoleMockRepo struct {
	mock.Mock
}

func (m *UserRoleMockRepo) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	args := m.Called(ctx, namespace)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserRole), args.Error(1)
}
func (m *UserRoleMockRepo) UpsertUserRole(ctx context.Context, role *model.UserRole) error {
	return m.Called(ctx, role).Error(0)
}
func (m *UserRoleMockRepo) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	args := m.Called(ctx, userID, namespace, role)
	return args.Bool(0), args.Error(1)
}
func (m *UserRoleMockRepo) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}
func (m *UserRoleMockRepo) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	args := m.Called(ctx, namespace)
	return int64(args.Int(0)), args.Error(1)
}

// Unused but required by interface
func (m *UserRoleMockRepo) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	return nil
}
func (m *UserRoleMockRepo) EnsureIndexes(ctx context.Context) error { return nil }
func (m *UserRoleMockRepo) TransferSystemOwner(ctx context.Context, ns, o, n string) error {
	return nil
}
func (m *UserRoleMockRepo) DeleteUserRole(ctx context.Context, ns, u, s string) error { return nil }

func TestPostSystemUserRole(t *testing.T) {
	t.Run("assign system admin role success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles", h.PostUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "ns_1", []string{model.RoleSystemOwner, model.RoleSystemAdmin}).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "ns_1").Return(nil, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Role == "admin" && r.UserID == "u_2"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: "ns_1", Scope: "system"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("assign system viewer role success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_viewer", h.PostUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "ns_1", []string{model.RoleSystemOwner, model.RoleSystemAdmin}).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "ns_1").Return(nil, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Role == "viewer" && r.UserID == "u_3"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "u_3", Role: "viewer", Namespace: "ns_1", Scope: "system"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_viewer", reqBody, map[string]string{"x-user-id": "admin_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("edit existing system user role success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_edit", h.PostUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "ns_1", []string{model.RoleSystemOwner, model.RoleSystemAdmin}).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "ns_1").Return(nil, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Role == "editor" && r.UserID == "u_existing"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "u_existing", Role: "editor", Namespace: "ns_1", Scope: "system"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_edit", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("edit system role forbidden (cannot downgrade last owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_downgrade", h.PostUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "ns_1", []string{model.RoleSystemOwner, model.RoleSystemAdmin}).Return(true, nil)

		currentOwner := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("GetSystemOwner", mock.Anything, "ns_1").Return(currentOwner, nil)
		mockRepo.On("CountSystemOwners", mock.Anything, "ns_1").Return(1, nil)

		reqBody := model.SystemUserRole{UserID: "owner_1", Role: "admin", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_downgrade", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign system role forbidden (admin trying to assign owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_bad_role", h.PostUserRoles)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "owner", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_bad_role", reqBody, map[string]string{"x-user-id": "admin_1", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign system role invalid role value and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_invalid", h.PostUserRoles)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "god_mode", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_invalid", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system role forbidden (caller not owner/admin) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_forbidden_caller", h.PostUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "ns_1", []string{model.RoleSystemOwner, model.RoleSystemAdmin}).Return(false, nil)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "viewer", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_forbidden_caller", reqBody, map[string]string{"x-user-id": "u_common", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign system role missing namespace and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_missing_ns", h.PostUserRoles)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: ""}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_missing_ns", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system role missing user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_missing_uid", h.PostUserRoles)

		reqBody := model.SystemUserRole{UserID: "", Role: "admin", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_missing_uid", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("assign system role unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_401", h.PostUserRoles)

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: "ns_1"}
		// Missing authentication / x-user-id (if x-user-id missing, handler returns 401)
		rec := PerformRequest(e, http.MethodPost, "/user_roles_401", reqBody, map[string]string{})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign system role internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(UserRoleMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_500", h.PostUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "ns_1", []string{model.RoleSystemOwner, model.RoleSystemAdmin}).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "ns_1").Return(nil, nil)
		mockRepo.On("UpsertUserRole", mock.Anything, mock.Anything).Return(errors.New("db error"))

		reqBody := model.SystemUserRole{UserID: "u_2", Role: "admin", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_500", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
