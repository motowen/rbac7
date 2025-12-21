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
	"go.mongodb.org/mongo-driver/mongo"
)

type DeleteMockRepo struct {
	mock.Mock
}

func (m *DeleteMockRepo) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	args := m.Called(ctx, namespace)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserRole), args.Error(1)
}
func (m *DeleteMockRepo) DeleteUserRole(ctx context.Context, ns, u, s, d string) error {
	return m.Called(ctx, ns, u, s, d).Error(0)
}
func (m *DeleteMockRepo) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	args := m.Called(ctx, userID, namespace, role)
	return args.Bool(0), args.Error(1)
}
func (m *DeleteMockRepo) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}

func (m *DeleteMockRepo) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	return nil, nil
}

func (m *DeleteMockRepo) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	args := m.Called(ctx, namespace)
	return int64(args.Int(0)), args.Error(1)
}
func (m *DeleteMockRepo) UpsertUserRole(ctx context.Context, role *model.UserRole) error { return nil }
func (m *DeleteMockRepo) CreateUserRole(ctx context.Context, role *model.UserRole) error { return nil }
func (m *DeleteMockRepo) EnsureIndexes(ctx context.Context) error                        { return nil }
func (m *DeleteMockRepo) TransferSystemOwner(ctx context.Context, ns, o, n string) error { return nil }

func TestDeleteSystemUserRole(t *testing.T) {
	t.Run("remove system member success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles", h.DeleteUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_2", "system", "owner_1").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/user_roles?namespace=ns_1&user_id=u_2", nil, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("remove system member missing parameters and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles_bad", h.DeleteUserRoles)

		// Missing user_id
		rec := PerformRequest(e, http.MethodDelete, "/user_roles_bad?namespace=ns_1", nil, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("remove system member unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles_401", h.DeleteUserRoles)

		rec := PerformRequest(e, http.MethodDelete, "/user_roles_401?namespace=ns_1&user_id=u_2", nil, map[string]string{})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("remove system member forbidden (cannot delete last owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles_own", h.DeleteUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)

		ownerRole := &model.UserRole{UserID: "u_target", Role: model.RoleSystemOwner}
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("CountSystemOwners", mock.Anything, "NS_1").Return(1, nil)

		rec := PerformRequest(e, http.MethodDelete, "/user_roles_own?namespace=ns_1&user_id=u_target", nil, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove system member forbidden (missing delete permission) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles_403", h.DeleteUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "NS_1", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodDelete, "/user_roles_403?namespace=ns_1&user_id=u_2", nil, map[string]string{"x-user-id": "u_common", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove system member forbidden should not reveal existence and return 403 even if target not found", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles_403_reveal", h.DeleteUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "NS_1", mock.Anything).Return(false, nil)

		// Note: Service checks auth FIRST before checking if target user exists or is owner.
		// So it returns 403 immediately without checking GetAll or specific user role.
		// This satisfies "not reveal existence".

		rec := PerformRequest(e, http.MethodDelete, "/user_roles_403_reveal?namespace=ns_1&user_id=u_ghost", nil, map[string]string{"x-user-id": "u_common", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("remove system member twice should be idempotent and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles_idempotent", h.DeleteUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		// Repo returns ErrNoDocuments -> Service converts to nil/success
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_2", "system", "owner_1").Return(mongo.ErrNoDocuments)

		rec := PerformRequest(e, http.MethodDelete, "/user_roles_idempotent?namespace=ns_1&user_id=u_2", nil, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("remove system member internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(DeleteMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE("/user_roles_500", h.DeleteUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_2", "system", "owner_1").Return(errors.New("db error"))

		rec := PerformRequest(e, http.MethodDelete, "/user_roles_500?namespace=ns_1&user_id=u_2", nil, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
