package tests

import (
	"context"
	"system/internal/system/client"
	"system/internal/system/model"
	"system/internal/system/repository"
	"time"
)

// MockSystemRepository is a mock implementation of SystemRepository
type MockSystemRepository struct {
	CreateSystemFunc           func(ctx context.Context, system *model.System) error
	UpdateSystemFunc           func(ctx context.Context, namespace string, name, description *string) (*model.System, error)
	GetSystemByNamespaceFunc   func(ctx context.Context, namespace string) (*model.System, error)
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
	CheckPermissionFunc   func(ctx context.Context, callerID, permission, namespace string) (bool, error)
	AssignSystemOwnerFunc func(ctx context.Context, callerID, ownerID, namespace string) error
	GetUserRolesMeFunc    func(ctx context.Context, callerID string) ([]client.UserRole, error)
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
	CreateLibraryWidgetFunc       func(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error)
	UpdateLibraryWidgetFunc       func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error)
	DeleteLibraryWidgetFunc       func(ctx context.Context, id string) error
	GetLibraryWidgetFunc          func(ctx context.Context, id string) (*model.LibraryWidget, error)
	GetLibraryWidgetsFunc         func(ctx context.Context) ([]*model.LibraryWidget, error)
	UpdateLibraryWidgetStatusFunc func(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error)
	SaveToHistoryFunc             func(ctx context.Context, widgetID string, publishedBy string) error
	GetHistoryFunc                func(ctx context.Context, widgetID string) ([]*model.LibraryWidgetHistory, error)
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

func (m *MockWidgetRepository) UpdateLibraryWidgetStatus(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error) {
	if m.UpdateLibraryWidgetStatusFunc != nil {
		return m.UpdateLibraryWidgetStatusFunc(ctx, id, status, previousStatus)
	}
	return &model.LibraryWidget{ID: id, Status: status}, nil
}

func (m *MockWidgetRepository) SaveToHistory(ctx context.Context, widgetID string, publishedBy string) error {
	if m.SaveToHistoryFunc != nil {
		return m.SaveToHistoryFunc(ctx, widgetID, publishedBy)
	}
	return nil
}

func (m *MockWidgetRepository) GetHistory(ctx context.Context, widgetID string) ([]*model.LibraryWidgetHistory, error) {
	if m.GetHistoryFunc != nil {
		return m.GetHistoryFunc(ctx, widgetID)
	}
	return []*model.LibraryWidgetHistory{}, nil
}

// MockDashboardRepository is a mock implementation of DashboardRepository
type MockDashboardRepository struct {
	CreateDashboardFunc       func(ctx context.Context, dashboard *model.Dashboard) (*model.Dashboard, error)
	GetDashboardFunc          func(ctx context.Context, id string) (*model.Dashboard, error)
	GetDashboardsFunc         func(ctx context.Context) ([]*model.Dashboard, error)
	UpdateDashboardFunc       func(ctx context.Context, id string, update *repository.DashboardUpdate) (*model.Dashboard, error)
	UpdateDashboardStatusFunc func(ctx context.Context, id string, status string, previousStatus string) (*model.Dashboard, error)

	AddWidgetToDashboardFunc    func(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error)
	UpdateDashboardWidgetFunc   func(ctx context.Context, id string, update *repository.DashboardWidgetUpdate) (*model.DashboardWidget, error)
	RemoveDashboardWidgetFunc   func(ctx context.Context, id string) error
	GetDashboardWidgetFunc      func(ctx context.Context, id string) (*model.DashboardWidget, error)
	GetDashboardWidgetsFunc     func(ctx context.Context, dashboardID string, version string) ([]*model.DashboardWidget, error)
	CopyWidgetsToDraftFunc      func(ctx context.Context, dashboardID string) error
	PromoteDraftToPublishedFunc func(ctx context.Context, dashboardID string) error
	DeleteWidgetsByVersionFunc  func(ctx context.Context, dashboardID string, version string) error

	SaveToHistoryFunc func(ctx context.Context, dashboardID string, publishedBy string) error
	GetHistoryFunc    func(ctx context.Context, dashboardID string) ([]*model.DashboardHistory, error)
}

func (m *MockDashboardRepository) CreateDashboard(ctx context.Context, dashboard *model.Dashboard) (*model.Dashboard, error) {
	if m.CreateDashboardFunc != nil {
		return m.CreateDashboardFunc(ctx, dashboard)
	}
	dashboard.ID = "mock-dashboard-id"
	dashboard.Status = model.StatusDraft
	return dashboard, nil
}

func (m *MockDashboardRepository) GetDashboard(ctx context.Context, id string) (*model.Dashboard, error) {
	if m.GetDashboardFunc != nil {
		return m.GetDashboardFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockDashboardRepository) GetDashboards(ctx context.Context) ([]*model.Dashboard, error) {
	if m.GetDashboardsFunc != nil {
		return m.GetDashboardsFunc(ctx)
	}
	return []*model.Dashboard{}, nil
}

func (m *MockDashboardRepository) UpdateDashboard(ctx context.Context, id string, update *repository.DashboardUpdate) (*model.Dashboard, error) {
	if m.UpdateDashboardFunc != nil {
		return m.UpdateDashboardFunc(ctx, id, update)
	}
	return &model.Dashboard{ID: id}, nil
}

func (m *MockDashboardRepository) UpdateDashboardStatus(ctx context.Context, id string, status string, previousStatus string) (*model.Dashboard, error) {
	if m.UpdateDashboardStatusFunc != nil {
		return m.UpdateDashboardStatusFunc(ctx, id, status, previousStatus)
	}
	return &model.Dashboard{ID: id, Status: status}, nil
}

func (m *MockDashboardRepository) AddWidgetToDashboard(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error) {
	if m.AddWidgetToDashboardFunc != nil {
		return m.AddWidgetToDashboardFunc(ctx, widget)
	}
	widget.ID = "mock-widget-id"
	return widget, nil
}

func (m *MockDashboardRepository) UpdateDashboardWidget(ctx context.Context, id string, update *repository.DashboardWidgetUpdate) (*model.DashboardWidget, error) {
	if m.UpdateDashboardWidgetFunc != nil {
		return m.UpdateDashboardWidgetFunc(ctx, id, update)
	}
	return &model.DashboardWidget{ID: id}, nil
}

func (m *MockDashboardRepository) RemoveDashboardWidget(ctx context.Context, id string) error {
	if m.RemoveDashboardWidgetFunc != nil {
		return m.RemoveDashboardWidgetFunc(ctx, id)
	}
	return nil
}

func (m *MockDashboardRepository) GetDashboardWidget(ctx context.Context, id string) (*model.DashboardWidget, error) {
	if m.GetDashboardWidgetFunc != nil {
		return m.GetDashboardWidgetFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockDashboardRepository) GetDashboardWidgets(ctx context.Context, dashboardID string, version string) ([]*model.DashboardWidget, error) {
	if m.GetDashboardWidgetsFunc != nil {
		return m.GetDashboardWidgetsFunc(ctx, dashboardID, version)
	}
	return []*model.DashboardWidget{}, nil
}

func (m *MockDashboardRepository) CopyWidgetsToDraft(ctx context.Context, dashboardID string) error {
	if m.CopyWidgetsToDraftFunc != nil {
		return m.CopyWidgetsToDraftFunc(ctx, dashboardID)
	}
	return nil
}

func (m *MockDashboardRepository) PromoteDraftToPublished(ctx context.Context, dashboardID string) error {
	if m.PromoteDraftToPublishedFunc != nil {
		return m.PromoteDraftToPublishedFunc(ctx, dashboardID)
	}
	return nil
}

func (m *MockDashboardRepository) DeleteWidgetsByVersion(ctx context.Context, dashboardID string, version string) error {
	if m.DeleteWidgetsByVersionFunc != nil {
		return m.DeleteWidgetsByVersionFunc(ctx, dashboardID, version)
	}
	return nil
}

func (m *MockDashboardRepository) SaveToHistory(ctx context.Context, dashboardID string, publishedBy string) error {
	if m.SaveToHistoryFunc != nil {
		return m.SaveToHistoryFunc(ctx, dashboardID, publishedBy)
	}
	return nil
}

func (m *MockDashboardRepository) GetHistory(ctx context.Context, dashboardID string) ([]*model.DashboardHistory, error) {
	if m.GetHistoryFunc != nil {
		return m.GetHistoryFunc(ctx, dashboardID)
	}
	return []*model.DashboardHistory{}, nil
}

// MockLockRepository is a mock implementation of LockRepository
type MockLockRepository struct {
	LockFunc            func(ctx context.Context, entityType, entityID, userID string, duration time.Duration) (*model.EntityLock, error)
	UnlockFunc          func(ctx context.Context, entityType, entityID, userID string) error
	GetLockFunc         func(ctx context.Context, entityType, entityID string) (*model.EntityLock, error)
	IsLockedByOtherFunc func(ctx context.Context, entityType, entityID, userID string) (bool, error)
	EnsureIndexesFunc   func(ctx context.Context) error
}

func (m *MockLockRepository) Lock(ctx context.Context, entityType, entityID, userID string, duration time.Duration) (*model.EntityLock, error) {
	if m.LockFunc != nil {
		return m.LockFunc(ctx, entityType, entityID, userID, duration)
	}
	return &model.EntityLock{EntityType: entityType, EntityID: entityID, LockedBy: userID}, nil
}

func (m *MockLockRepository) Unlock(ctx context.Context, entityType, entityID, userID string) error {
	if m.UnlockFunc != nil {
		return m.UnlockFunc(ctx, entityType, entityID, userID)
	}
	return nil
}

func (m *MockLockRepository) GetLock(ctx context.Context, entityType, entityID string) (*model.EntityLock, error) {
	if m.GetLockFunc != nil {
		return m.GetLockFunc(ctx, entityType, entityID)
	}
	return nil, nil
}

func (m *MockLockRepository) IsLockedByOther(ctx context.Context, entityType, entityID, userID string) (bool, error) {
	if m.IsLockedByOtherFunc != nil {
		return m.IsLockedByOtherFunc(ctx, entityType, entityID, userID)
	}
	return false, nil
}

func (m *MockLockRepository) EnsureIndexes(ctx context.Context) error {
	if m.EnsureIndexesFunc != nil {
		return m.EnsureIndexesFunc(ctx)
	}
	return nil
}
