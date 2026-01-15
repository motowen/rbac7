package tests

import (
	"context"
	"system/internal/system/client"
	"system/internal/system/model"
)

// MockSystemRepository is a mock implementation of SystemRepository
type MockSystemRepository struct {
	// CreateSystemFunc mocks the CreateSystem method
	CreateSystemFunc func(ctx context.Context, system *model.System) error
	// UpdateSystemFunc mocks the UpdateSystem method
	UpdateSystemFunc func(ctx context.Context, namespace string, name, description *string) (*model.System, error)
	// GetSystemByNamespaceFunc mocks the GetSystemByNamespace method
	GetSystemByNamespaceFunc func(ctx context.Context, namespace string) (*model.System, error)
	// GetSystemsByNamespacesFunc mocks the GetSystemsByNamespaces method
	GetSystemsByNamespacesFunc func(ctx context.Context, namespaces []string) ([]*model.System, error)
}

func (m *MockSystemRepository) CreateSystem(ctx context.Context, system *model.System) error {
	if m.CreateSystemFunc != nil {
		return m.CreateSystemFunc(ctx, system)
	}
	return nil
}

func (m *MockSystemRepository) UpdateSystem(ctx context.Context, namespace string, name, description *string) (*model.System, error) {
	if m.UpdateSystemFunc != nil {
		return m.UpdateSystemFunc(ctx, namespace, name, description)
	}
	return &model.System{Namespace: namespace}, nil
}

func (m *MockSystemRepository) GetSystemByNamespace(ctx context.Context, namespace string) (*model.System, error) {
	if m.GetSystemByNamespaceFunc != nil {
		return m.GetSystemByNamespaceFunc(ctx, namespace)
	}
	return nil, nil
}

func (m *MockSystemRepository) GetSystemsByNamespaces(ctx context.Context, namespaces []string) ([]*model.System, error) {
	if m.GetSystemsByNamespacesFunc != nil {
		return m.GetSystemsByNamespacesFunc(ctx, namespaces)
	}
	return []*model.System{}, nil
}

// MockRBACClient is a mock implementation for RBAC client
type MockRBACClient struct {
	// CheckPermissionFunc mocks CheckPermission
	CheckPermissionFunc func(ctx context.Context, callerID, permission, namespace string) (bool, error)
	// AssignSystemOwnerFunc mocks AssignSystemOwner
	AssignSystemOwnerFunc func(ctx context.Context, callerID, ownerID, namespace string) error
	// GetUserRolesMeFunc mocks GetUserRolesMe
	GetUserRolesMeFunc func(ctx context.Context, callerID string) ([]client.UserRole, error)
}

func (m *MockRBACClient) CheckPermission(ctx context.Context, callerID, permission, namespace string) (bool, error) {
	if m.CheckPermissionFunc != nil {
		return m.CheckPermissionFunc(ctx, callerID, permission, namespace)
	}
	return true, nil
}

func (m *MockRBACClient) AssignSystemOwner(ctx context.Context, callerID, ownerID, namespace string) error {
	if m.AssignSystemOwnerFunc != nil {
		return m.AssignSystemOwnerFunc(ctx, callerID, ownerID, namespace)
	}
	return nil
}

func (m *MockRBACClient) GetUserRolesMe(ctx context.Context, callerID string) ([]client.UserRole, error) {
	if m.GetUserRolesMeFunc != nil {
		return m.GetUserRolesMeFunc(ctx, callerID)
	}
	return []client.UserRole{}, nil
}
