package tests

import (
	"context"
	"testing"

	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDashboardWidgetPermissions(t *testing.T) {
	// Constants and Policy Mapping Tests
	t.Run("Check Constants", func(t *testing.T) {
		assert.Equal(t, "resource.dashboard.add_widget", model.PermResourceDashboardAddWidget)
		assert.Equal(t, "resource.dashboard_widget.read", model.PermResourceDashboardWidgetRead)
	})

	t.Run("Policy Mappings", func(t *testing.T) {
		// Owner should have add_widget
		roles := service.GetResourceRolesWithPermission(model.PermResourceDashboardAddWidget)
		assert.Contains(t, roles, "owner")
		assert.Contains(t, roles, "admin")
		assert.Contains(t, roles, "editor")
		assert.NotContains(t, roles, "viewer")

		// Viewer should have whitelisted read (via generic mapping)
		rolesRead := service.GetResourceRolesWithPermission(model.PermResourceDashboardWidgetRead)
		assert.Contains(t, rolesRead, "viewer")
	})

	// Service Logic Tests (Inheritance vs Whitelist)
	t.Run("CheckPermission Service Logic", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		ctx := context.TODO()

		// Scenario 1: Inherited Read (Widget has 0 roles) -> Checks Parent
		// Mock CountResourceRoles(widget1) -> 0
		// Mock HasAnyResourceRole(user1, dashboard1, dashboard, ...) -> true
		mockRepo.On("CountResourceRoles", ctx, "widget1", "dashboard_widget").Return(int64(0), nil)
		// CheckCommon logic calls HasResourcePermission -> HasAnyResourceRole
		mockRepo.On("HasAnyResourceRole", ctx, "user1", "dashboard1", "dashboard", mock.Anything).Return(true, nil)

		reqInherit := model.CheckPermissionReq{
			Permission:       model.PermResourceDashboardWidgetRead,
			Scope:            model.ScopeResource,
			ResourceID:       "widget1",
			ResourceType:     "dashboard_widget",
			ParentResourceID: "dashboard1",
		}

		allowed, err := svc.CheckPermission(ctx, "user1", reqInherit)
		assert.NoError(t, err)
		assert.True(t, allowed)

		// Scenario 2: Whitelisted Read (Widget has roles) -> Checks Widget Strictly
		// Mock CountResourceRoles(widget2) -> 1
		// Mock HasAnyResourceRole(user2, widget2, dashboard_widget, ...) -> false (User denied on widget)
		mockRepo.On("CountResourceRoles", ctx, "widget2", "dashboard_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", ctx, "user2", "widget2", "dashboard_widget", mock.Anything).Return(false, nil)

		reqWhitelistDeny := model.CheckPermissionReq{
			Permission:       model.PermResourceDashboardWidgetRead,
			Scope:            model.ScopeResource,
			ResourceID:       "widget2",
			ResourceType:     "dashboard_widget",
			ParentResourceID: "dashboard1",
		}

		allowedDeny, errDeny := svc.CheckPermission(ctx, "user2", reqWhitelistDeny)
		assert.NoError(t, errDeny)
		assert.False(t, allowedDeny)

		// Scenario 3: Whitelisted Read (Widget has roles) -> Checks Widget Strictly (Allow)
		// Mock CountResourceRoles(widget3) -> 1
		// Mock HasAnyResourceRole(user3, widget3, dashboard_widget, ...) -> true (User allowed on widget)
		mockRepo.On("CountResourceRoles", ctx, "widget3", "dashboard_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", ctx, "user3", "widget3", "dashboard_widget", mock.Anything).Return(true, nil)

		reqWhitelistAllow := model.CheckPermissionReq{
			Permission:       model.PermResourceDashboardWidgetRead,
			Scope:            model.ScopeResource,
			ResourceID:       "widget3",
			ResourceType:     "dashboard_widget",
			ParentResourceID: "dashboard1",
		}

		allowedAllow, errAllow := svc.CheckPermission(ctx, "user3", reqWhitelistAllow)
		assert.NoError(t, errAllow)
		assert.True(t, allowedAllow)
	})
	t.Run("Validation Logic", func(t *testing.T) {
		// Case 1: Dashboard Widget missing ParentResourceID -> Error
		req := model.CheckPermissionReq{
			Permission:   model.PermResourceDashboardWidgetRead,
			Scope:        model.ScopeResource,
			ResourceID:   "w1",
			ResourceType: "dashboard_widget",
		}
		err := req.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parent_resource_id is required")

		// Case 2: Dashboard Widget with ParentResourceID -> OK
		req.ParentResourceID = "d1"
		err = req.Validate()
		assert.NoError(t, err)

		// Case 3: Other Resource (e.g. Dashboard) missing ParentResourceID -> OK
		reqDashboard := model.CheckPermissionReq{
			Permission:   model.PermResourceDashboardRead,
			Scope:        model.ScopeResource,
			ResourceID:   "d1",
			ResourceType: "dashboard",
		}
		err = reqDashboard.Validate()
		assert.NoError(t, err)
	})

	t.Run("Assign Widget Viewer Permission Check", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		ctx := context.TODO()

		// Expect check for "resource.dashboard.add_widget_viewer" ON PARENT (d1)
		mockRepo.On("HasAnyResourceRole", ctx, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)
		// Mock Upsert
		mockRepo.On("UpsertUserRole", ctx, mock.Anything).Return(nil)
		// Mock HasResourceRole (Owner check)
		mockRepo.On("HasResourceRole", ctx, "target", "w1", "dashboard_widget", "owner").Return(false, nil)

		req := model.AssignResourceUserRoleReq{
			UserID:           "target",
			Role:             "viewer",
			ResourceType:     "dashboard_widget",
			ResourceID:       "w1",
			ParentResourceID: "d1",
		}

		err := svc.AssignResourceUserRole(ctx, "caller", req)
		assert.NoError(t, err)

		mockRepo.AssertExpectations(t)
	})

	t.Run("Delete Widget Viewer Permission Check", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		ctx := context.TODO()

		// 1. Mock HasResourceRole(target, viewer) -> true (Target IS a viewer)
		mockRepo.On("HasResourceRole", ctx, "target", "w1", "dashboard_widget", "viewer").Return(true, nil)

		// 2. Expect check for "resource.dashboard.add_widget_viewer" ON PARENT (d1)
		mockRepo.On("HasAnyResourceRole", ctx, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)

		// 3. Check Owner (prevent delete owner) -> false
		mockRepo.On("HasResourceRole", ctx, "target", "w1", "dashboard_widget", "owner").Return(false, nil)

		// 4. Delete
		mockRepo.On("DeleteUserRole", ctx, "", "target", "resource", "w1", "dashboard_widget", "caller").Return(nil)

		req := model.DeleteResourceUserRoleReq{
			UserID:           "target",
			ResourceType:     "dashboard_widget",
			ResourceID:       "w1",
			ParentResourceID: "d1",
		}

		err := svc.DeleteResourceUserRole(ctx, "caller", req)
		assert.NoError(t, err)

		mockRepo.AssertExpectations(t)
	})
}
