package tests

import (
	"context"
	"system/internal/system/client"
	"system/internal/system/model"
	"system/internal/system/repository"
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

// MockWidgetRepository is a mock implementation of WidgetRepository
type MockWidgetRepository struct {
	// Library Widget mocks
	CreateLibraryWidgetFunc func(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error)
	UpdateLibraryWidgetFunc func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error)
	DeleteLibraryWidgetFunc func(ctx context.Context, id string) error
	GetLibraryWidgetFunc    func(ctx context.Context, id string) (*model.LibraryWidget, error)
	GetLibraryWidgetsFunc   func(ctx context.Context) ([]*model.LibraryWidget, error)

	// Dashboard Widget mocks
	CreateDashboardWidgetFunc func(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error)
	UpdateDashboardWidgetFunc func(ctx context.Context, id string, layout *model.DashboardWidgetLayout) (*model.DashboardWidget, error)
	DeleteDashboardWidgetFunc func(ctx context.Context, id string) error
	GetDashboardWidgetFunc    func(ctx context.Context, id string) (*model.DashboardWidget, error)
	GetDashboardWidgetsFunc   func(ctx context.Context, dashboardID string) ([]*model.DashboardWidget, error)
}

func (m *MockWidgetRepository) CreateLibraryWidget(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error) {
	if m.CreateLibraryWidgetFunc != nil {
		return m.CreateLibraryWidgetFunc(ctx, widget)
	}
	widget.ID = "mock-id"
	return widget, nil
}

func (m *MockWidgetRepository) UpdateLibraryWidget(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
	if m.UpdateLibraryWidgetFunc != nil {
		return m.UpdateLibraryWidgetFunc(ctx, id, update)
	}
	return &model.LibraryWidget{ID: id}, nil
}

func (m *MockWidgetRepository) DeleteLibraryWidget(ctx context.Context, id string) error {
	if m.DeleteLibraryWidgetFunc != nil {
		return m.DeleteLibraryWidgetFunc(ctx, id)
	}
	return nil
}

func (m *MockWidgetRepository) GetLibraryWidget(ctx context.Context, id string) (*model.LibraryWidget, error) {
	if m.GetLibraryWidgetFunc != nil {
		return m.GetLibraryWidgetFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockWidgetRepository) GetLibraryWidgets(ctx context.Context) ([]*model.LibraryWidget, error) {
	if m.GetLibraryWidgetsFunc != nil {
		return m.GetLibraryWidgetsFunc(ctx)
	}
	return []*model.LibraryWidget{}, nil
}

func (m *MockWidgetRepository) CreateDashboardWidget(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error) {
	if m.CreateDashboardWidgetFunc != nil {
		return m.CreateDashboardWidgetFunc(ctx, widget)
	}
	widget.ID = "mock-id"
	return widget, nil
}

func (m *MockWidgetRepository) UpdateDashboardWidget(ctx context.Context, id string, layout *model.DashboardWidgetLayout) (*model.DashboardWidget, error) {
	if m.UpdateDashboardWidgetFunc != nil {
		return m.UpdateDashboardWidgetFunc(ctx, id, layout)
	}
	return &model.DashboardWidget{ID: id}, nil
}

func (m *MockWidgetRepository) DeleteDashboardWidget(ctx context.Context, id string) error {
	if m.DeleteDashboardWidgetFunc != nil {
		return m.DeleteDashboardWidgetFunc(ctx, id)
	}
	return nil
}

func (m *MockWidgetRepository) GetDashboardWidget(ctx context.Context, id string) (*model.DashboardWidget, error) {
	if m.GetDashboardWidgetFunc != nil {
		return m.GetDashboardWidgetFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockWidgetRepository) GetDashboardWidgets(ctx context.Context, dashboardID string) ([]*model.DashboardWidget, error) {
	if m.GetDashboardWidgetsFunc != nil {
		return m.GetDashboardWidgetsFunc(ctx, dashboardID)
	}
	return []*model.DashboardWidget{}, nil
}
