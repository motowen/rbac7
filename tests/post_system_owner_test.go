package tests

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mock Utils for this test ---

// MockRepo satisfies repository.RBACRepository
type MockRepo struct {
	mock.Mock
}

func (m *MockRepo) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	args := m.Called(ctx, namespace)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserRole), args.Error(1)
}

func (m *MockRepo) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRepo) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	args := m.Called(ctx, userID, namespace, role)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepo) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepo) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	return nil, nil
}

func (m *MockRepo) EnsureIndexes(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRepo) TransferSystemOwner(ctx context.Context, namespace, oldOwnerID, newOwnerID string) error {
	args := m.Called(ctx, namespace, oldOwnerID, newOwnerID)
	return args.Error(0)
}

func (m *MockRepo) UpsertUserRole(ctx context.Context, role *model.UserRole) error { return nil }
func (m *MockRepo) DeleteUserRole(ctx context.Context, namespace, userID, scope, deletedBy string) error {
	return nil
}
func (m *MockRepo) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	return 0, nil
}

// --- Test Implementation ---

func TestPostSystemOwner(t *testing.T) {
	t.Run("moderator assign system owner success and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner", h.PostSystemOwner)

		// 1. Role Check (Policy Engine uses HasAnySystemRole for add_owner permission)
		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		// 2. Create (GetSystemOwner Removed from Service logic, relies on DB constraint/err now)
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "u_1",
			Namespace: "ns_success",
		}

		headers := map[string]string{
			"authentication": "Bearer token",
			"x-user-id":      "moderator_1",
		}

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner", reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("assign system owner with whitespace inputs success", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner_trim", h.PostSystemOwner)

		// Expect TRIMMED values in calls
		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		mockRepo.On("CreateUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.Namespace == "NS_TRIM" && r.UserID == "u_trim"
		})).Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "  u_trim  ",
			Namespace: "  ns_trim  ",
		}
		headers := map[string]string{"authentication": "Bearer token", "x-user-id": "moderator_1"}

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner_trim", reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("assign system owner missing namespace and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner_400", h.PostSystemOwner)

		// Validation happens FIRST now
		// So no Repo calls expected

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "u_1",
			Namespace: "", // Missing
		}
		headers := map[string]string{
			"authentication": "Bearer token",
			"x-user-id":      "moderator_1",
		}

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner_400", reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("assign system owner missing user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner_400_u", h.PostSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{
			UserID:    "", // Missing
			Namespace: "ns",
		}
		headers := map[string]string{
			"authentication": "Bearer token",
			"x-user-id":      "moderator_1",
		}

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner_400_u", reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("assign system owner unauthorized (empty caller) and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		// No service call expected if handler auth fails first
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner_401", h.PostSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns"}
		// No x-user-id

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner_401", reqBody, map[string]string{"authentication": "Bearer t"})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("assign system owner forbidden (not moderator) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner_403", h.PostSystemOwner)

		// Role Check -> False
		mockRepo.On("HasAnySystemRole", mock.Anything, "u_common", "", mock.Anything).Return(false, nil)

		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns", UserID: "u_1"}
		headers := map[string]string{
			"authentication": "Bearer token",
			"x-user-id":      "u_common",
		}

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner_403", reqBody, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("assign system owner already exists (conflict) and return 409", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner_409", h.PostSystemOwner)

		// 1. Role Check -> True
		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		// 2. Create -> ErrConflict (simulated via Repo ErrDuplicate)
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(repository.ErrDuplicate)

		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns_conflict", UserID: "u_1"}
		headers := map[string]string{
			"authentication": "Bearer token",
			"x-user-id":      "moderator_1",
		}

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner_409", reqBody, headers)
		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("assign system owner internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles/owner_500", h.PostSystemOwner)

		// 1. Role Check -> True
		mockRepo.On("HasAnySystemRole", mock.Anything, "moderator_1", "", mock.Anything).Return(true, nil)
		// 2. Create -> Error
		mockRepo.On("CreateUserRole", mock.Anything, mock.Anything).Return(errors.New("db disconnect"))

		reqBody := model.SystemOwnerUpsertRequest{Namespace: "ns_error", UserID: "u_1"}
		headers := map[string]string{
			"authentication": "Bearer token",
			"x-user-id":      "moderator_1",
		}

		rec := PerformRequest(e, http.MethodPost, "/user_roles/owner_500", reqBody, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
