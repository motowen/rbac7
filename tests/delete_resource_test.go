package tests

import (
	"net/http"
	"testing"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestDeleteResource tests PUT /api/v1/resources/delete
// This API soft-deletes a resource and its associated user roles
func TestDeleteResource(t *testing.T) {
	apiPath := "/api/v1/resources/delete"

	// ============================================================================
	// Dashboard Delete Tests
	// Permission: resource.dashboard.delete on the dashboard itself
	// Behavior: Soft delete all user roles for dashboard + all child widgets
	// ============================================================================

	t.Run("delete dashboard success with child_widget_ids and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: check permission on dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		// Service: soft delete user roles for dashboard and child widgets
		mockRepo.On("SoftDeleteResourceUserRoles", mock.Anything, mock.MatchedBy(func(req model.SoftDeleteResourceReq) bool {
			return req.ResourceID == "d1" &&
				req.ResourceType == "dashboard" &&
				len(req.ChildResourceIDs) == 2
		}), "owner_1").Return(nil)

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1", "w2"},
		}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("delete dashboard success without child_widget_ids and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		mockRepo.On("SoftDeleteResourceUserRoles", mock.Anything, mock.MatchedBy(func(req model.SoftDeleteResourceReq) bool {
			return req.ResourceID == "d1" &&
				req.ResourceType == "dashboard" &&
				len(req.ChildResourceIDs) == 0
		}), "owner_1").Return(nil)

		payload := map[string]interface{}{
			"resource_id":   "d1",
			"resource_type": "dashboard",
			// No child_resource_ids - valid case
		}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("delete dashboard forbidden when no permission and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: no permission
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1"},
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("delete dashboard missing resource_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1"},
		}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================================
	// Dashboard Widget Delete Tests
	// Permission: resource.dashboard.delete on PARENT dashboard
	// Behavior: Soft delete all user roles for the widget
	// ============================================================================

	t.Run("delete dashboard_widget success with parent_resource_id and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: check permission on PARENT dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		// Service: soft delete user roles for widget
		mockRepo.On("SoftDeleteResourceUserRoles", mock.Anything, mock.MatchedBy(func(req model.SoftDeleteResourceReq) bool {
			return req.ResourceID == "w1" &&
				req.ResourceType == "dashboard_widget" &&
				req.ParentResourceID == "d1"
		}), "owner_1").Return(nil)

		payload := map[string]interface{}{
			"resource_id":        "w1",
			"resource_type":      "dashboard_widget",
			"parent_resource_id": "d1",
		}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("delete dashboard_widget forbidden when no permission on parent and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: no permission on parent dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "d1", "dashboard", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"resource_id":        "w1",
			"resource_type":      "dashboard_widget",
			"parent_resource_id": "d1",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("delete dashboard_widget missing parent_resource_id and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_id":   "w1",
			"resource_type": "dashboard_widget",
			// missing parent_resource_id
		}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================================
	// Library Widget Delete Tests
	// Permission: system.resource.delete on namespace
	// Behavior: Soft delete all user roles for the library widget
	// ============================================================================

	t.Run("delete library_widget success with namespace and return 200", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: check system permission on namespace (uppercased)
		mockRepo.On("HasAnySystemRole", mock.Anything, "admin_1", "NS1", mock.Anything).Return(true, nil)

		// Service: soft delete user roles for library widget (namespace uppercased by Validate())
		mockRepo.On("SoftDeleteResourceUserRoles", mock.Anything, mock.MatchedBy(func(req model.SoftDeleteResourceReq) bool {
			return req.ResourceID == "lw1" &&
				req.ResourceType == "library_widget" &&
				req.Namespace == "NS1" // Uppercased by Validate()
		}), "admin_1").Return(nil)

		payload := map[string]interface{}{
			"resource_id":   "lw1",
			"resource_type": "library_widget",
			"namespace":     "ns1",
		}
		headers := map[string]string{"x-user-id": "admin_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("delete library_widget forbidden when no system permission and return 403", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: no permission
		mockRepo.On("HasAnySystemRole", mock.Anything, "user_1", "NS1", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"resource_id":   "lw1",
			"resource_type": "library_widget",
			"namespace":     "ns1",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("delete library_widget missing namespace and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_id":   "lw1",
			"resource_type": "library_widget",
			// missing namespace
		}
		headers := map[string]string{"x-user-id": "admin_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================================
	// General Tests
	// ============================================================================

	t.Run("delete resource unauthorized and return 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_id":   "d1",
			"resource_type": "dashboard",
		}
		// No x-user-id header

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("delete resource invalid resource_type and return 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_id":   "x1",
			"resource_type": "unknown_type",
		}
		headers := map[string]string{"x-user-id": "user_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("delete resource internal error and return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission granted
		mockRepo.On("HasAnyResourceRole", mock.Anything, "owner_1", "d1", "dashboard", mock.Anything).Return(true, nil)

		// Service: returns error
		mockRepo.On("SoftDeleteResourceUserRoles", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)

		payload := map[string]interface{}{
			"resource_id":        "d1",
			"resource_type":      "dashboard",
			"child_resource_ids": []string{"w1"},
		}
		headers := map[string]string{"x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, apiPath, payload, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
