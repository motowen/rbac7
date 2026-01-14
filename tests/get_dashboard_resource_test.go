package tests

import (
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestGetDashboardResource tests POST /api/v1/resources/dashboards
// Returns dashboard user roles + accessible widget IDs based on permission
func TestGetDashboardResource(t *testing.T) {
	apiPath := "/api/v1/resources/dashboards"

	// ============================================================================
	// Success Cases
	// ============================================================================

	t.Run("TC1: get dashboard with no child widgets and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: check permission on dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		// Service: get dashboard user roles
		dashboardRoles := []*model.UserRole{
			{UserID: "owner_1", Role: "owner", ResourceID: "d1", ResourceType: "dashboard", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.ResourceID == "d1" && f.ResourceType == "dashboard" && f.Scope == "resource"
		})).Return(dashboardRoles, nil)

		payload := map[string]interface{}{
			"resource_id":   "d1",
			"resource_type": "dashboard",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "owner_1")
		assert.Contains(t, rec.Body.String(), "accessible_widget_ids")
		mockRepo.AssertExpectations(t)
	})

	t.Run("TC2: get dashboard with all widgets inheriting (no whitelist) and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		dashboardRoles := []*model.UserRole{
			{UserID: "owner_1", Role: "owner", ResourceID: "d1", ResourceType: "dashboard", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.ResourceID == "d1" && f.ResourceType == "dashboard"
		})).Return(dashboardRoles, nil)

		// Widgets have 0 roles (inherit from parent)
		mockRepo.On("CountResourceRoles", mock.Anything, "w1", "dashboard_widget").Return(int64(0), nil)
		mockRepo.On("CountResourceRoles", mock.Anything, "w2", "dashboard_widget").Return(int64(0), nil)

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1", "w2"},
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "w1")
		assert.Contains(t, rec.Body.String(), "w2")
		mockRepo.AssertExpectations(t)
	})

	t.Run("TC3: get dashboard with some whitelisted widgets (caller in some) and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		dashboardRoles := []*model.UserRole{
			{UserID: "owner_1", Role: "owner", ResourceID: "d1", ResourceType: "dashboard", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.ResourceID == "d1" && f.ResourceType == "dashboard"
		})).Return(dashboardRoles, nil)

		// w1: 0 roles (inherit) -> accessible
		mockRepo.On("CountResourceRoles", mock.Anything, "w1", "dashboard_widget").Return(int64(0), nil)
		// w2: has roles, caller IS in whitelist -> accessible
		mockRepo.On("CountResourceRoles", mock.Anything, "w2", "dashboard_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "w2", "dashboard_widget", mock.Anything).Return(true, nil)
		// w3: has roles, caller NOT in whitelist -> NOT accessible
		mockRepo.On("CountResourceRoles", mock.Anything, "w3", "dashboard_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "w3", "dashboard_widget", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1", "w2", "w3"},
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "w1")
		assert.Contains(t, rec.Body.String(), "w2")
		assert.NotContains(t, rec.Body.String(), `"w3"`)
		mockRepo.AssertExpectations(t)
	})

	t.Run("TC4: get dashboard with all whitelisted widgets (caller has none) and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		dashboardRoles := []*model.UserRole{
			{UserID: "owner_1", Role: "owner", ResourceID: "d1", ResourceType: "dashboard", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.ResourceID == "d1" && f.ResourceType == "dashboard"
		})).Return(dashboardRoles, nil)

		// All widgets have roles, caller NOT in whitelist
		mockRepo.On("CountResourceRoles", mock.Anything, "w1", "dashboard_widget").Return(int64(2), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "w1", "dashboard_widget", mock.Anything).Return(false, nil)
		mockRepo.On("CountResourceRoles", mock.Anything, "w2", "dashboard_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "w2", "dashboard_widget", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1", "w2"},
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		// accessible_widget_ids should be empty
		assert.Contains(t, rec.Body.String(), `"accessible_widget_ids":[]`)
		mockRepo.AssertExpectations(t)
	})

	t.Run("TC5: get dashboard with all whitelisted widgets (caller has all) and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		dashboardRoles := []*model.UserRole{
			{UserID: "owner_1", Role: "owner", ResourceID: "d1", ResourceType: "dashboard", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.MatchedBy(func(f model.UserRoleFilter) bool {
			return f.ResourceID == "d1" && f.ResourceType == "dashboard"
		})).Return(dashboardRoles, nil)

		// All widgets have roles, caller IS in whitelist for all
		mockRepo.On("CountResourceRoles", mock.Anything, "w1", "dashboard_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "w1", "dashboard_widget", mock.Anything).Return(true, nil)
		mockRepo.On("CountResourceRoles", mock.Anything, "w2", "dashboard_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "w2", "dashboard_widget", mock.Anything).Return(true, nil)

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1", "w2"},
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "w1")
		assert.Contains(t, rec.Body.String(), "w2")
		mockRepo.AssertExpectations(t)
	})

	// ============================================================================
	// Permission Denied Cases
	// ============================================================================

	t.Run("TC6: no permission on dashboard and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"resource_id":   "d1",
			"resource_type": "dashboard",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	// ============================================================================
	// Validation Error Cases
	// ============================================================================

	t.Run("TC7: missing resource_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_type": "dashboard",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("TC8: missing resource_type and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_id": "d1",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================================
	// Authentication Cases
	// ============================================================================

	t.Run("TC9: no x-user-id header and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_id":   "d1",
			"resource_type": "dashboard",
		}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	// ============================================================================
	// Internal Error Cases
	// ============================================================================

	t.Run("TC10: repository error when fetching dashboard roles and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		payload := map[string]interface{}{
			"resource_id":   "d1",
			"resource_type": "dashboard",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("TC11: repository error when counting widget roles and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		dashboardRoles := []*model.UserRole{
			{UserID: "owner_1", Role: "owner", ResourceID: "d1", ResourceType: "dashboard", Scope: "resource"},
		}
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return(dashboardRoles, nil)
		mockRepo.On("CountResourceRoles", mock.Anything, "w1", "dashboard_widget").Return(int64(0), errors.New("db error"))

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1"},
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPost, apiPath, payload, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
