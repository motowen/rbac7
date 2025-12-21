package tests

import (
	"context"
	"net/http"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Define local mock to avoid conflicts and specifically checking for Calls if needed
type ResurrectionMockRepo struct {
	mock.Mock
}

func (m *ResurrectionMockRepo) UpsertUserRole(ctx context.Context, role *model.UserRole) error {
	return m.Called(ctx, role).Error(0)
}
func (m *ResurrectionMockRepo) TransferSystemOwner(ctx context.Context, ns, o, n string) error {
	return m.Called(ctx, ns, o, n).Error(0)
}
func (m *ResurrectionMockRepo) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	args := m.Called(ctx, namespace)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserRole), args.Error(1)
}
func (m *ResurrectionMockRepo) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	args := m.Called(ctx, userID, namespace, role)
	return args.Bool(0), args.Error(1)
}
func (m *ResurrectionMockRepo) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}
func (m *ResurrectionMockRepo) DeleteUserRole(ctx context.Context, ns, u, s, d string) error {
	return m.Called(ctx, ns, u, s, d).Error(0)
}
func (m *ResurrectionMockRepo) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	args := m.Called(ctx, namespace)
	return int64(args.Int(0)), args.Error(1)
}

// Unused stubs
func (m *ResurrectionMockRepo) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	return nil
}
func (m *ResurrectionMockRepo) EnsureIndexes(ctx context.Context) error { return nil }
func (m *ResurrectionMockRepo) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	return nil, nil
}

func TestResurrectionFlows(t *testing.T) {
	// Case 1: Deleted user becomes Owner via Transfer
	t.Run("resurrect deleted user via owner transfer", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(ResurrectionMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner", h.PutSystemOwner)

		// Setup: Caller is current owner
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)

		// Expect Transfer call. The Repo implementation handles the actual "unset deleted_at" logic.
		// Detailed repo tests would be needed to verify DB state, but here we verify flow allows it.
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "deleted_user").Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "deleted_user", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	// Case 2: Deleted user becomes Member via Assign (admin/dev/viewer)
	t.Run("resurrect deleted user as admin via assign", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(ResurrectionMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles", h.PostUserRoles)

		// Caller has permission
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)

		// Expect Upsert. Service sets Audit fields (UpdatedBy etc).
		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.UserID == "deleted_user" && r.Role == "admin" && r.UpdatedBy == "owner_1"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "deleted_user", Role: "admin", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("resurrect deleted user as viewer via assign", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(ResurrectionMockRepo)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.POST("/user_roles_v", h.PostUserRoles)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(nil, nil)

		mockRepo.On("UpsertUserRole", mock.Anything, mock.MatchedBy(func(r *model.UserRole) bool {
			return r.UserID == "deleted_user_2" && r.Role == "viewer"
		})).Return(nil)

		reqBody := model.SystemUserRole{UserID: "deleted_user_2", Role: "viewer", Namespace: "ns_1"}
		rec := PerformRequest(e, http.MethodPost, "/user_roles_v", reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
