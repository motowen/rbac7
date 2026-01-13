package tests

import (
	"context"
	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/mock"
)

// MockRBACRepository is a shared mock implementation of repository.RBACRepository for testing.
type MockRBACRepository struct {
	mock.Mock
}

func (m *MockRBACRepository) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	args := m.Called(ctx, namespace)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserRole), args.Error(1)
}

func (m *MockRBACRepository) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRBACRepository) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	args := m.Called(ctx, userID, namespace, role)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACRepository) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, namespace, roles)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACRepository) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.UserRole), args.Error(1)
}

func (m *MockRBACRepository) EnsureIndexes(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRBACRepository) TransferSystemOwner(ctx context.Context, namespace, oldOwnerID, newOwnerID, updatedBy string) error {
	args := m.Called(ctx, namespace, oldOwnerID, newOwnerID, updatedBy)
	return args.Error(0)
}

func (m *MockRBACRepository) UpsertUserRole(ctx context.Context, role *model.UserRole) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRBACRepository) DeleteUserRole(ctx context.Context, namespace, userID, scope, resourceID, resourceType, deletedBy string) error {
	args := m.Called(ctx, namespace, userID, scope, resourceID, resourceType, deletedBy)
	return args.Error(0)
}

func (m *MockRBACRepository) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	args := m.Called(ctx, namespace)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRBACRepository) HasResourceRole(ctx context.Context, userID, resourceID, resourceType, role string) (bool, error) {
	args := m.Called(ctx, userID, resourceID, resourceType, role)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACRepository) HasAnyResourceRole(ctx context.Context, userID, resourceID, resourceType string, roles []string) (bool, error) {
	args := m.Called(ctx, userID, resourceID, resourceType, roles)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACRepository) TransferResourceOwner(ctx context.Context, resourceID, resourceType, oldOwnerID, newOwnerID, updatedBy string) error {
	args := m.Called(ctx, resourceID, resourceType, oldOwnerID, newOwnerID, updatedBy)
	return args.Error(0)
}

func (m *MockRBACRepository) CountResourceOwners(ctx context.Context, resourceID, resourceType string) (int64, error) {
	args := m.Called(ctx, resourceID, resourceType)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRBACRepository) CountResourceRoles(ctx context.Context, resourceID, resourceType string) (int64, error) {
	args := m.Called(ctx, resourceID, resourceType)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRBACRepository) BulkUpsertUserRoles(ctx context.Context, roles []*model.UserRole) (*model.BatchUpsertResult, error) {
	args := m.Called(ctx, roles)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.BatchUpsertResult), args.Error(1)
}

func (m *MockRBACRepository) SoftDeleteResourceUserRoles(ctx context.Context, req model.SoftDeleteResourceReq, deletedBy string) error {
	args := m.Called(ctx, req, deletedBy)
	return args.Error(0)
}
