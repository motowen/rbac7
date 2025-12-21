package tests

import (
	"context"
	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/mock"
)

type MockRBACService struct {
	mock.Mock
}

func (m *MockRBACService) AssignSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error {
	args := m.Called(ctx, callerID, req)
	return args.Error(0)
}

func (m *MockRBACService) TransferSystemOwner(ctx context.Context, callerID string, req model.SystemOwnerUpsertRequest) error {
	args := m.Called(ctx, callerID, req)
	return args.Error(0)
}

func (m *MockRBACService) AssignSystemUserRole(ctx context.Context, callerID string, req model.SystemUserRole) error {
	args := m.Called(ctx, callerID, req)
	return args.Error(0)
}

func (m *MockRBACService) DeleteSystemUserRole(ctx context.Context, callerID, namespace, userID string) error {
	args := m.Called(ctx, callerID, namespace, userID)
	return args.Error(0)
}

func (m *MockRBACService) GetUserRolesMe(ctx context.Context, callerID, scope string) ([]*model.UserRole, error) {
	args := m.Called(ctx, callerID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.UserRole), args.Error(1)
}

func (m *MockRBACService) GetUserRoles(ctx context.Context, callerID string, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	args := m.Called(ctx, callerID, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.UserRole), args.Error(1)
}

func (m *MockRBACService) AssignResourceOwner(ctx context.Context, callerID, namespace string, req model.ResourceOwnerUpsertRequest) error {
	args := m.Called(ctx, callerID, namespace, req)
	return args.Error(0)
}

func (m *MockRBACService) TransferResourceOwner(ctx context.Context, callerID, namespace string, req model.ResourceOwnerUpsertRequest) error {
	args := m.Called(ctx, callerID, namespace, req)
	return args.Error(0)
}

func (m *MockRBACService) AssignResourceUserRole(ctx context.Context, callerID string, req model.ResourceUserRole) error {
	args := m.Called(ctx, callerID, req)
	return args.Error(0)
}

func (m *MockRBACService) DeleteResourceUserRole(ctx context.Context, callerID, namespace, resourceID, resourceType, userID string) error {
	args := m.Called(ctx, callerID, namespace, resourceID, resourceType, userID)
	return args.Error(0)
}
