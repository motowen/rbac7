package tests

import (
	"context"
	"testing"

	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/policy"
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
		engine, err := policy.NewEngine()
		assert.NoError(t, err)

		// Owner should have add_widget
		roles := engine.GetRolesWithPermission(model.PermResourceDashboardAddWidget, false)
		assert.Contains(t, roles, "owner")
		assert.Contains(t, roles, "admin")
		assert.Contains(t, roles, "editor")
		assert.NotContains(t, roles, "viewer")

		// Viewer should have whitelisted read (via generic mapping)
		rolesRead := engine.GetRolesWithPermission(model.PermResourceDashboardWidgetRead, false)
		assert.Contains(t, rolesRead, "viewer")
	})

	// Service Logic Tests (Inheritance vs Whitelist) via CheckPermission API
	t.Run("CheckPermission Service Logic", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		ctx := context.TODO()

		// Scenario 1: Inherited Read (Widget has 0 roles) -> Checks Parent
		mockRepo.On("CountResourceRoles", ctx, "widget1", "dashboard_widget").Return(int64(0), nil)
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

	// Service layer tests: Permission check is now handled by middleware
	// These tests only verify business logic (owner check, upsert, delete)
	t.Run("Assign Widget Viewer Business Logic", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		ctx := context.TODO()

		// Mock HasResourceRole (Owner check) -> target is not owner
		mockRepo.On("HasResourceRole", ctx, "target", "w1", "dashboard_widget", "owner").Return(false, nil)
		// Mock Upsert
		mockRepo.On("UpsertUserRole", ctx, mock.Anything).Return(nil)

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

	t.Run("Delete Widget Viewer Business Logic", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		ctx := context.TODO()

		// 1. Check Owner (prevent delete owner) -> false
		mockRepo.On("HasResourceRole", ctx, "target", "w1", "dashboard_widget", "owner").Return(false, nil)

		// 2. Delete
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
