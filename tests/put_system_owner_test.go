package tests

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Reuse MockRepo structure but we must define methods on it LOCALLY to this test file
// if we want to avoid redeclaration issues or just define a local mock type.
// Since Go doesn't allow method redeclaration in same package if in same file set?
// Actually different files in same package same struct name is fine if they are essentially same type,
// but redeclaring method in different files for same type?
// It's safer to define a distinct MockRepo for this test or share one in helper.
// Let's define `PutOwnerMockRepo` to avoid conflicts.

type PutOwnerMockRepo struct {
	mock.Mock
}

func (m *PutOwnerMockRepo) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	args := m.Called(ctx, namespace)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserRole), args.Error(1)
}

func (m *PutOwnerMockRepo) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *PutOwnerMockRepo) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	args := m.Called(ctx, userID, namespace, role)
	return args.Bool(0), args.Error(1)
}

func (m *PutOwnerMockRepo) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}

func (m *PutOwnerMockRepo) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	return nil, nil
}

func (m *PutOwnerMockRepo) EnsureIndexes(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *PutOwnerMockRepo) TransferSystemOwner(ctx context.Context, namespace, oldOwnerID, newOwnerID string) error {
	args := m.Called(ctx, namespace, oldOwnerID, newOwnerID)
	return args.Error(0)
}

func (m *PutOwnerMockRepo) UpsertUserRole(ctx context.Context, role *model.UserRole) error {
	return nil
}
func (m *PutOwnerMockRepo) DeleteUserRole(ctx context.Context, namespace, userID, scope, deletedBy string) error {
	return nil
}
func (m *PutOwnerMockRepo) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	return 0, nil
}

func TestPutSystemOwner(t *testing.T) {
	t.Run("transfer system owner success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner", h.PutSystemOwner)

		// 1. Service calls GetSystemOwner to verify caller is owner
		// 1. Service calls GetSystemOwner to verify caller is owner
		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		// Permission Check (Platform.system.transfer_owner)
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)

		// 2. Transfer
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "new_owner").Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_1"}
		headers := map[string]string{
			"authentication": "Bearer t",
			"x-user-id":      "owner_1",
		}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner", reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("transfer system owner old owner becomes admin (implied) and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_admin", h.PutSystemOwner)

		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "new_owner").Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_admin", reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("transfer system owner missing new user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_400", h.PutSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_400", reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner to same user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_same", h.PutSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "owner_1", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_same", reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_401", h.PutSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "u", Namespace: "ns"}
		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_401", reqBody, map[string]string{})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("transfer system owner forbidden (caller not current owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_403", h.PutSystemOwner)

		// Permission Check -> False
		mockRepo.On("HasAnySystemRole", mock.Anything, "fake_owner", "NS_1", mock.Anything).Return(false, nil)
		// GetSystemOwner is NOT called if permission denied

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "fake_owner"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_403", reqBody, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("transfer system owner target user not found and return 404", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_404", h.PutSystemOwner)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_MISSING", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_MISSING").Return(nil, nil)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_missing"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_404", reqBody, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("transfer system owner internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(PutOwnerMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_500", h.PutSystemOwner)

		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "new_owner").Return(errors.New("db error"))

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_500", reqBody, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
